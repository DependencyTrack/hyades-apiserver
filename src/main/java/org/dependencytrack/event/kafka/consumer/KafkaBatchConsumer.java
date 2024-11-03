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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.binder.BaseUnits;
import org.apache.kafka.clients.consumer.ConsumerRebalanceListener;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.errors.WakeupException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

public abstract class KafkaBatchConsumer<K, V> implements Runnable, ConsumerRebalanceListener {

    enum State {

        CREATED(1),            // 0
        RUNNING(2, 3),         // 1
        PAUSED_RETRY(1, 2, 3), // 2
        STOPPING(4),           // 3
        STOPPED(1);            // 4

        private final Set<Integer> allowedTransitions;

        State(final Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(final State newState) {
            return allowedTransitions.contains(newState.ordinal());
        }

        private boolean isPausedForRetry() {
            return equals(State.PAUSED_RETRY);
        }

        private boolean isNotStoppingOrStopped() {
            return !equals(STOPPING) && !equals(STOPPED);
        }

    }

    private static final String METER_PREFIX = "dtrack.kafka.batch.consumer.";

    private volatile State state = State.CREATED;
    private final ReentrantLock stateLock = new ReentrantLock();
    private final Map<TopicPartition, OffsetAndMetadata> pendingOffsetByTopicPartition = new HashMap<>();
    private final Map<TopicPartition, OffsetAndMetadata> committableOffsetByTopicPartition = new HashMap<>();
    private final Map<TopicPartition, OffsetAndMetadata> lastCommittedOffsetByTopicPartition = new HashMap<>();
    private final List<ConsumerRecord<K, V>> recordBatch = new ArrayList<>();

    private final Logger logger;
    private final KafkaConsumer<K, V> kafkaConsumer;
    private final Duration batchLingerDuration;
    private final int batchSize;

    private Gauge batchRecordsGaugeMeter;
    private DistributionSummary flushBatchSizeDistributionMeter;
    private Counter flushCounterMeter;

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

    /**
     * Whether the given {@link ConsumerRecord} should be added to the batch.
     * <p>
     * Offsets of skipped records will still be committed.
     *
     * @param record The {@link ConsumerRecord} to inspect.
     * @return {@code true} when it should be added, otherwise {@code false}.
     */
    protected boolean shouldAddToBatch(final ConsumerRecord<K, V> record) {
        return true;
    }

    /**
     * Flush the current batch of {@link ConsumerRecord}s.
     * <p>
     * The batch is guaranteed to contain at least one record.
     * It may contain more records than {@link #batchSize}.
     * <p>
     * The implementation should be idempotent.
     *
     * @param records The batch of {@link ConsumerRecord}s to flush.
     * @return {@code true} when the batch was flushed successfully, otherwise {@code false}.
     * When encountering errors, an exception should be thrown rather than returning {@code false}.
     */
    protected abstract boolean flushBatch(final List<ConsumerRecord<K, V>> records);

    @Override
    public void run() {
        setState(State.RUNNING);
        maybeInitializeMeters();
        lastFlushedAt = Instant.now();

        while (state.isNotStoppingOrStopped()) {
            final ConsumerRecords<K, V> records;
            try {
                // TODO: Use exponential backoff for poll timeout in case we're paused for retry.
                records = kafkaConsumer.poll(Duration.ofSeconds(1));
            } catch (WakeupException e) {
                logger.debug("Consumer woke up during poll", e);
                continue;
            }
            if (records.isEmpty()) {
                logger.debug("Poll did not yield any records");
                final boolean flushed = maybeFlushBatch();
                if (!flushed) {
                    maybeCommitOffsets(kafkaConsumer.assignment());
                }

                continue;
            }

            logger.debug("Poll yielded %d records".formatted(records.count()));
            var shouldTryFlushBatch = true;
            for (final ConsumerRecord<K, V> record : records) {
                if (shouldAddToBatch(record)) {
                    recordBatch.add(record);
                }

                pendingOffsetByTopicPartition.put(
                        new TopicPartition(record.topic(), record.partition()),
                        new OffsetAndMetadata(record.offset() + 1));
                if (shouldTryFlushBatch) {
                    // When currently paused for retry, only attempt to flush once for this poll.
                    // Note that the batch will keep growing as long as poll returns records,
                    // even if it exceeds the configured batchSize.
                    final boolean didFlush = maybeFlushBatch();
                    if (!didFlush && state.isPausedForRetry()) {
                        shouldTryFlushBatch = false;
                    }
                }
            }
        }

        maybeCleanMeters();
        setState(State.STOPPED);
    }

    public void shutdown() {
        setState(State.STOPPING);
        kafkaConsumer.wakeup();
    }

    @Override
    public void onPartitionsAssigned(final Collection<TopicPartition> topicPartitions) {
        logger.debug("Partitions assigned: " + topicPartitions);

        for (final TopicPartition topicPartition : topicPartitions) {
            final long consumerPosition = kafkaConsumer.position(topicPartition);
            final var offset = new OffsetAndMetadata(consumerPosition);
            lastCommittedOffsetByTopicPartition.put(topicPartition, offset);
        }

        if (state.isPausedForRetry()) {
            if (recordBatch.isEmpty()) {
                // We previously paused for retry, but all partitions with
                // our to-be-retried records have been revoked.
                kafkaConsumer.resume(kafkaConsumer.assignment());
                setState(State.RUNNING);
            } else {
                // Ensure pausing continues even for newly assigned partitions.
                kafkaConsumer.pause(kafkaConsumer.assignment());
            }
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

        if (flushCounterMeter != null) {
            flushCounterMeter.increment();
        }

        final int batchSize = recordBatch.size();
        logger.debug("Flushing batch of %d records".formatted(batchSize));
        if (flushBatchSizeDistributionMeter != null) {
            flushBatchSizeDistributionMeter.record(batchSize);
        }

        final boolean didFlush;
        try {
            didFlush = flushBatch(List.copyOf(recordBatch));
        } catch (AssertionError | IllegalStateException e) { // Use dedicated exception for this.
            logger.warn("""
                    Encountered retryable exception while flushing batch; \
                    Pausing consumption from %s""".formatted(kafkaConsumer.assignment()), e);
            kafkaConsumer.pause(kafkaConsumer.assignment());
            setState(State.PAUSED_RETRY);
            return false;
        }
        if (!didFlush) {
            return false;
        }

        committableOffsetByTopicPartition.putAll(pendingOffsetByTopicPartition);
        pendingOffsetByTopicPartition.clear();
        recordBatch.clear();
        lastFlushedAt = Instant.now();

        maybeCommitOffsets(committableOffsetByTopicPartition.keySet());

        if (state.isPausedForRetry()) {
            logger.info("Resuming consumption from %s".formatted(kafkaConsumer.assignment()));
            kafkaConsumer.resume(kafkaConsumer.assignment());
            setState(State.RUNNING);
        }

        return true;
    }

    private boolean shouldFlushBatch() {
        if (recordBatch.size() >= batchSize) {
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

        if (logger.isDebugEnabled()) {
            logger.debug("Committing offsets: " + offsetToCommitByTopicPartition);
        }

        try {
            // TODO: Handle timeout, retries of commit request?
            kafkaConsumer.commitSync(offsetToCommitByTopicPartition);
        } catch (WakeupException e) {
            logger.debug("Consumer woke up during commit");
            maybeCommitOffsets(topicPartitions);
            throw e;
        }

        lastCommittedOffsetByTopicPartition.putAll(offsetToCommitByTopicPartition);
    }

    State state() {
        return state;
    }

    private void setState(final State newState) {
        stateLock.lock();
        try {
            if (this.state.canTransitionTo(newState)) {
                this.state = newState;
                kafkaConsumer.wakeup();
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from state %s to %s".formatted(this.state, newState));
        } finally {
            stateLock.unlock();
        }
    }

    private void maybeInitializeMeters() {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            return;
        }

        batchRecordsGaugeMeter = Gauge.builder(METER_PREFIX + "batch.records", recordBatch::size)
                .description("Number of records currently in the batch")
                .baseUnit(BaseUnits.OBJECTS)
                .tag("name", getClass().getSimpleName())
                .register(Metrics.getRegistry());
        flushBatchSizeDistributionMeter = DistributionSummary.builder(METER_PREFIX + "flush.batch.size")
                .description("Size of batches being flushed")
                .baseUnit(BaseUnits.OBJECTS)
                .tag("name", getClass().getSimpleName())
                .register(Metrics.getRegistry());
        flushCounterMeter = Counter.builder(METER_PREFIX + "flush")
                .description("Number of flush operations")
                .baseUnit(BaseUnits.OPERATIONS)
                .tag("name", getClass().getSimpleName())
                .register(Metrics.getRegistry());
    }

    private void maybeCleanMeters() {
        if (!Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            return;
        }

        Metrics.getRegistry().remove(batchRecordsGaugeMeter);
        Metrics.getRegistry().remove(flushCounterMeter);
        Metrics.getRegistry().remove(flushBatchSizeDistributionMeter);

        batchRecordsGaugeMeter = null;
        flushCounterMeter = null;
        flushBatchSizeDistributionMeter = null;
    }

}
