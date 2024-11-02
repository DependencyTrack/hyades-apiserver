/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.event.kafka.consumer;

import alpine.common.logging.Logger;
import org.apache.kafka.clients.consumer.ConsumerRebalanceListener;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public abstract class KafkaBatchConsumer<K, V> implements Runnable, ConsumerRebalanceListener {

    private final AtomicBoolean isRunning = new AtomicBoolean(true);
    private final Map<TopicPartition, OffsetAndMetadata> pendingOffsetByTopicPartition = new HashMap<>();
    private final Map<TopicPartition, OffsetAndMetadata> committableOffsetByTopicPartition = new HashMap<>();
    private final Map<TopicPartition, OffsetAndMetadata> lastCommittedOffsetByTopicPartition = new HashMap<>();
    private final List<ConsumerRecord<K, V>> recordBatch = new ArrayList<>();

    private final Logger logger;
    private final KafkaConsumer<K, V> kafkaConsumer;
    private final Duration batchLingerDuration;
    private final int batchSize;

    private Instant lastFlushedAt;

    protected KafkaBatchConsumer(
            final KafkaConsumer<K, V> kafkaConsumer,
            final Duration batchLingerDuration,
            final int batchSize) {
        this.logger = Logger.getLogger(getClass());
        this.kafkaConsumer = kafkaConsumer;
        this.batchLingerDuration = batchLingerDuration;
        this.batchSize = batchSize;
    }
    
    protected boolean filterBatchRecord(final ConsumerRecord<K, V> record) {
        return true;
    }

    protected abstract boolean flushBatch(final List<ConsumerRecord<K, V>> records);

    @Override
    public void run() {
        while (isRunning.get()) {
            final ConsumerRecords<K, V> records = kafkaConsumer.poll(Duration.ofSeconds(1));
            if (records.isEmpty()) {
                logger.debug("Poll did not yield any records");
                final boolean flushed = maybeFlushBatch();
                if (!flushed) {
                    maybeCommitOffsets(kafkaConsumer.assignment());
                }

                continue;
            }

            for (final ConsumerRecord<K, V> record : records) {
                final var topicPartition = new TopicPartition(record.topic(), record.partition());

                if (filterBatchRecord(record)) {
                    recordBatch.add(record);
                }

                pendingOffsetByTopicPartition.put(topicPartition, new OffsetAndMetadata(record.offset() + 1));
                maybeFlushBatch();
            }
        }
    }

    public void shutdown() {
        isRunning.set(false);
    }

    @Override
    public void onPartitionsAssigned(final Collection<TopicPartition> topicPartitions) {
        logger.debug("Partitions assigned: " + topicPartitions);

        for (final TopicPartition topicPartition : topicPartitions) {
            final long consumerPosition = kafkaConsumer.position(topicPartition);
            final var offset = new OffsetAndMetadata(consumerPosition);
            lastCommittedOffsetByTopicPartition.put(topicPartition, offset);
        }
    }

    @Override
    public void onPartitionsRevoked(final Collection<TopicPartition> topicPartitions) {
        logger.debug("Partitions revoked: " + topicPartitions);
        onPartitionsRevoked(topicPartitions, /* lost */ false);
    }

    @Override
    public void onPartitionsLost(final Collection<TopicPartition> topicPartitions) {
        logger.debug("Partitions lost: " + topicPartitions);
        onPartitionsRevoked(topicPartitions, /* lost */ true);
    }

    private void onPartitionsRevoked(final Collection<TopicPartition> topicPartitions, final boolean lost) {
        if (lost) {
            pendingOffsetByTopicPartition.keySet().removeAll(topicPartitions);
            committableOffsetByTopicPartition.keySet().removeAll(topicPartitions);
        } else {
            maybeCommitOffsets(topicPartitions);
        }

        lastCommittedOffsetByTopicPartition.keySet().removeAll(topicPartitions);
        recordBatch.removeIf(record -> {
            final var recordTopicPartition = new TopicPartition(record.topic(), record.partition());
            return topicPartitions.contains(recordTopicPartition);
        });
    }

    private boolean maybeFlushBatch() {
        if (!shouldFlushBatch()) {
            return false;
        }

        if (recordBatch.isEmpty()) {
            return false;
        }

        // TODO: Catch exceptions, seek to last committed offset.
        final boolean wasFlushed = flushBatch(List.copyOf(recordBatch));
        if (!wasFlushed) {
            return false;
        }

        committableOffsetByTopicPartition.putAll(pendingOffsetByTopicPartition);
        pendingOffsetByTopicPartition.clear();
        recordBatch.clear();
        lastFlushedAt = Instant.now();

        maybeCommitOffsets(committableOffsetByTopicPartition.keySet());
        return true;
    }

    private boolean shouldFlushBatch() {
        if (recordBatch.size() >= batchSize) {
            return true;
        }
        if (lastFlushedAt == null) {
            return true;
        }

        final Duration durationSinceLastFlush = Duration.between(lastFlushedAt, Instant.now());
        return durationSinceLastFlush.compareTo(batchLingerDuration) >= 0;
    }

    private void maybeCommitOffsets(final Collection<TopicPartition> topicPartitions) {
        if (committableOffsetByTopicPartition.isEmpty()) {
            logger.debug("No committable offsets pending");
            return;
        }

        final Map<TopicPartition, OffsetAndMetadata> offsetToCommitByTopicPartition =
                committableOffsetByTopicPartition.entrySet().stream()
                        .filter(entry -> topicPartitions.contains(entry.getKey()))
                        .filter(entry -> {
                            final TopicPartition topicPartition = entry.getKey();
                            final OffsetAndMetadata offsetAndMetadataToCommit = entry.getValue();

                            final OffsetAndMetadata lastCommittedOffsetAndMetadata =
                                    lastCommittedOffsetByTopicPartition.get(topicPartition);
                            return lastCommittedOffsetAndMetadata == null
                                   || lastCommittedOffsetAndMetadata.offset() < offsetAndMetadataToCommit.offset();
                        })
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        if (offsetToCommitByTopicPartition.isEmpty()) {
            logger.debug("No offsets to commit for " + topicPartitions);
            return;
        }

        // TODO: Handle timeout, retries of commit request?
        if (logger.isDebugEnabled()) {
            logger.debug("Committing offsets: " + offsetToCommitByTopicPartition);
        }
        kafkaConsumer.commitSync(offsetToCommitByTopicPartition);
        lastCommittedOffsetByTopicPartition.putAll(offsetToCommitByTopicPartition);
    }

}
