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

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.MDC;

import java.util.UUID;
import java.util.concurrent.Callable;

import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_KEY;
import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_OFFSET;
import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_PARTITION;
import static org.dependencytrack.common.MdcKeys.MDC_KAFKA_RECORD_TOPIC;

/**
 * @since 5.6.0
 */
public final class ProcessorUtils {

    private ProcessorUtils() {
    }

    /**
     * Enriches the {@link MDC} with information about {@code record}, and executes {@code callable}.
     *
     * @param record   The {@link ConsumerRecord}
     * @param callable The {@link Callable} to execute
     * @param <T>      Type of {@code callable}'s return value
     * @return {@code callable}'s return value
     */
    public static <T> T withEnrichedMdc(final ConsumerRecord<?, ?> record, final Callable<T> callable) {
        try (var ignoredRecordTopic = MDC.putCloseable(MDC_KAFKA_RECORD_TOPIC, record.topic());
             var ignoredRecordPartition = MDC.putCloseable(MDC_KAFKA_RECORD_PARTITION, String.valueOf(record.partition()));
             var ignoredRecordOffset = MDC.putCloseable(MDC_KAFKA_RECORD_OFFSET, String.valueOf(record.offset()));
             var ignoredRecordKey = MDC.putCloseable(MDC_KAFKA_RECORD_KEY, printableKey(record))) {
            return callable.call();
        } catch (final Exception e) {
            if (e instanceof final RuntimeException re) {
                throw re;
            }

            throw new RuntimeException(e);
        }
    }

    private static String printableKey(final ConsumerRecord<?, ?> record) {
        if (record.key() instanceof final String key) {
            return key;
        } else if (record.key() instanceof final UUID key) {
            return key.toString();
        } else if (record.key() instanceof Number key) {
            return String.valueOf(key);
        } else if (record.key() instanceof Message key) {
            try {
                // JSON is easier to read than the default
                // text-based representation of Proto messages.
                return JsonFormat.printer()
                        .omittingInsignificantWhitespace()
                        .print(key);
            } catch (InvalidProtocolBufferException e) {
                return null;
            }
        }

        return null;
    }

}
