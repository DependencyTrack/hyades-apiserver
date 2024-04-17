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
package org.dependencytrack.event.kafka.processor;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.record.TimestampType;
import org.dependencytrack.PersistenceCapableTest;

import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNullElseGet;

abstract class AbstractProcessorTest extends PersistenceCapableTest {

    static <K, V> ConsumerRecordBuilder<K, V> aConsumerRecord(final K key, final V value) {
        return new ConsumerRecordBuilder<>(key, value);
    }

    static final class ConsumerRecordBuilder<K, V> {

        private final K key;
        private final V value;
        private Instant timestamp;
        private Headers headers;

        private ConsumerRecordBuilder(final K key, final V value) {
            this.key = key;
            this.value = value;
        }

        ConsumerRecordBuilder<K, V> withTimestamp(final Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        ConsumerRecordBuilder<K, V> withHeaders(final Headers headers) {
            this.headers = headers;
            return this;
        }

        ConsumerRecord<K, V> build() {
            final Instant timestamp = requireNonNullElseGet(this.timestamp, Instant::now);
            final Headers headers = requireNonNullElseGet(this.headers, RecordHeaders::new);
            return new ConsumerRecord<>(
                    "topicName",
                    /* partition */ 0,
                    /* offset */ 1,
                    timestamp.toEpochMilli(), TimestampType.CREATE_TIME,
                    /* serializedKeySize */ -1,
                    /* serializedValueSize */ -1,
                    this.key, this.value,
                    headers,
                    /* leaderEpoch */ Optional.empty());
        }

    }

}