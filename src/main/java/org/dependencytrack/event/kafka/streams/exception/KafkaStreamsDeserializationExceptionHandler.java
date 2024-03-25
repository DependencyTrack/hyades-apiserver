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
package org.dependencytrack.event.kafka.streams.exception;

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.streams.errors.DeserializationExceptionHandler;
import org.apache.kafka.streams.processor.ProcessorContext;
import org.dependencytrack.common.ConfigKey;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;

public class KafkaStreamsDeserializationExceptionHandler extends AbstractThresholdBasedExceptionHandler implements DeserializationExceptionHandler {

    private static final Logger LOGGER = Logger.getLogger(KafkaStreamsDeserializationExceptionHandler.class);


    @SuppressWarnings("unused") // Called by Kafka Streams via reflection
    public KafkaStreamsDeserializationExceptionHandler() {
        this(
                Clock.systemUTC(),
                Duration.parse(Config.getInstance().getProperty(ConfigKey.KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_INTERVAL)),
                Config.getInstance().getPropertyAsInt(ConfigKey.KAFKA_STREAMS_DESERIALIZATION_EXCEPTION_THRESHOLD_COUNT)
        );
    }

    KafkaStreamsDeserializationExceptionHandler(final Clock clock,
                                                final Duration exceptionThresholdInterval,
                                                final int exceptionThresholdCount) {
        super(clock, exceptionThresholdInterval, exceptionThresholdCount);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(final Map<String, ?> configs) {
        // Configuration is done via Alpine config.
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized DeserializationHandlerResponse handle(final ProcessorContext context,
                                                              final ConsumerRecord<byte[], byte[]> record,
                                                              final Exception exception) {
        // TODO: Use KafkaEventDispatcher to send the record to a dead letter topic?
        if (exceedsThreshold()) {
            LOGGER.error("""
                    Failed to deserialize record from topic %s (partition: %d, offset %d); \
                    Stopping to consume records, as the error was encountered %d times since %s, \
                    exceeding the configured threshold of %d occurrences in an interval of %s\
                    """
                    .formatted(record.topic(), record.partition(), record.offset(),
                            exceptionOccurrences(), firstExceptionOccurredAt(),
                            exceptionThresholdCount(), exceptionThresholdInterval()), exception);
            return DeserializationHandlerResponse.FAIL;
        }

        LOGGER.warn("""
                Failed to deserialize record from topic %s (partition: %d, offset: %d); \
                Skipping and continuing to consume records, as the configured threshold of \
                %d occurrences in an interval of %s has not been exceeded yet\
                """
                .formatted(record.topic(), record.partition(), record.offset(),
                        exceptionThresholdCount(), exceptionThresholdInterval()), exception);
        return DeserializationHandlerResponse.CONTINUE;
    }

}
