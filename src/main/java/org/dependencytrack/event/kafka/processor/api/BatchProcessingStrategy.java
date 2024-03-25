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
import org.dependencytrack.common.MdcKeys;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.List;

/**
 * A {@link ProcessingStrategy} that processes records in batches.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
class BatchProcessingStrategy<K, V> extends AbstractProcessingStrategy<K, V> {

    private static final Logger LOGGER = Logger.getLogger(BatchProcessingStrategy.class);

    private final BatchProcessor<K, V> batchProcessor;

    BatchProcessingStrategy(final BatchProcessor<K, V> batchProcessor,
                            final Serde<K> keySerde, final Serde<V> valueSerde) {
        super(keySerde, valueSerde);
        this.batchProcessor = batchProcessor;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void processRecords(final List<ConsumerRecord<byte[], byte[]>> records) {
        final var deserializedRecords = new ArrayList<ConsumerRecord<K, V>>(records.size());
        for (final ConsumerRecord<byte[], byte[]> record : records) {
            try (var ignoredMdcKafkaRecordTopic = MDC.putCloseable(MdcKeys.MDC_KAFKA_RECORD_TOPIC, record.topic());
                 var ignoredMdcKafkaRecordPartition = MDC.putCloseable(MdcKeys.MDC_KAFKA_RECORD_PARTITION, String.valueOf(record.partition()));
                 var ignoredMdcKafkaRecordOffset = MDC.putCloseable(MdcKeys.MDC_KAFKA_RECORD_OFFSET, String.valueOf(record.offset()))) {
                deserializedRecords.add(deserialize(record));
            } catch (SerializationException e) {
                // TODO: Consider supporting error handlers, e.g. to send record to DLT.
                LOGGER.error("Failed to deserialize record; Skipping", e);
            }
        }

        if (deserializedRecords.isEmpty()) {
            LOGGER.warn("All of the %d records in this batch failed to be deserialized".formatted(records.size()));
            return;
        }

        try {
            batchProcessor.process(deserializedRecords);
        } catch (ProcessingException | RuntimeException e) {
            if (isRetryableException(e)) {
                LOGGER.warn("Encountered retryable exception while processing %d records".formatted(deserializedRecords.size()), e);
                throw new PCRetriableException(e);
            }

            LOGGER.error("Encountered non-retryable exception while processing %d records; Skipping".formatted(deserializedRecords.size()), e);
            // TODO: Consider supporting error handlers, e.g. to send records to DLT.
            // Skip records to avoid poison-pill scenario.
        }
    }

}
