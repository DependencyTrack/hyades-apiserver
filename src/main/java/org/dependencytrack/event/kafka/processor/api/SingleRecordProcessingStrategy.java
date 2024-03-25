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
package org.dependencytrack.event.kafka.processor.api;

import alpine.common.logging.Logger;
import io.confluent.parallelconsumer.PCRetriableException;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.serialization.Serde;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.slf4j.MDC;

import java.util.List;

import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_KEY;
import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_OFFSET;
import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_PARTITION;
import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_TOPIC;

/**
 * A {@link ProcessingStrategy} that processes records individually.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
class SingleRecordProcessingStrategy<K, V> extends AbstractProcessingStrategy<K, V> {

    private static final Logger LOGGER = Logger.getLogger(SingleRecordProcessingStrategy.class);

    private final Processor<K, V> processor;

    SingleRecordProcessingStrategy(final Processor<K, V> processor,
                                   final Serde<K> keySerde, final Serde<V> valueSerde) {
        super(keySerde, valueSerde);
        this.processor = processor;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void processRecords(final List<ConsumerRecord<byte[], byte[]>> records) {
        if (records.isEmpty()) {
            return;
        }
        if (records.size() > 1) {
            throw new IllegalArgumentException("Expected at most one record, but received %d".formatted(records.size()));
        }

        final ConsumerRecord<byte[], byte[]> record = records.get(0);

        try (var ignoredMdcKafkaRecordTopic = MDC.putCloseable(MDC_KAFKA_RECORD_TOPIC, record.topic());
             var ignoredMdcKafkaRecordPartition = MDC.putCloseable(MDC_KAFKA_RECORD_PARTITION, String.valueOf(record.partition()));
             var ignoredMdcKafkaRecordOffset = MDC.putCloseable(MDC_KAFKA_RECORD_OFFSET, String.valueOf(record.offset()))) {
            processRecord(record);
        }
    }

    private void processRecord(final ConsumerRecord<byte[], byte[]> record) {
        final ConsumerRecord<K, V> deserializedRecord;
        try {
            deserializedRecord = deserialize(record);
        } catch (SerializationException e) {
            LOGGER.error("Failed to deserialize consumer record %s; Skipping", e);
            // TODO: Consider supporting error handlers, e.g. to send record to DLT.
            return; // Skip record to avoid poison-pill scenario.
        }

        try (var ignoredMdcKafkaRecordKey = MDC.putCloseable(MDC_KAFKA_RECORD_KEY, String.valueOf(deserializedRecord.key()))) {
            processor.process(deserializedRecord);
        } catch (ProcessingException | RuntimeException e) {
            if (isRetryableException(e)) {
                LOGGER.warn("Encountered retryable exception while processing record", e);
                throw new PCRetriableException(e);
            }

            LOGGER.error("Encountered non-retryable exception while processing record; Skipping", e);
            // TODO: Consider supporting error handlers, e.g. to send record to DLT.
            // Skip record to avoid poison-pill scenario.
        }
    }

}