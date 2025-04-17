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
package org.dependencytrack.event.kafka;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.notification.Notification;
import com.google.common.annotations.VisibleForTesting;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.Serde;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static java.util.concurrent.CompletableFuture.completedFuture;

/**
 * An {@link Event} dispatcher that wraps a Kafka {@link Producer}.
 */
public class KafkaEventDispatcher {

    private static final Logger LOGGER = Logger.getLogger(KafkaEventDispatcher.class);

    private final Producer<byte[], byte[]> producer;

    public KafkaEventDispatcher() {
        this(KafkaProducerInitializer.getProducer());
    }

    @VisibleForTesting
    KafkaEventDispatcher(final Producer<byte[], byte[]> producer) {
        this.producer = producer;
    }

    public CompletableFuture<RecordMetadata> dispatchEvent(final Event event) {
        if (event == null) {
            return completedFuture(null);
        }

        final KafkaEvent<?, ?> kafkaEvent = KafkaEventConverter.convert(event);
        return dispatchAll(List.of(kafkaEvent)).getFirst();
    }

    public CompletableFuture<RecordMetadata> dispatchNotification(final Notification notification) {
        if (notification == null) {
            return completedFuture(null);
        }

        final KafkaEvent<?, ?> kafkaEvent = KafkaEventConverter.convert(notification);
        return dispatchAll(List.of(kafkaEvent)).getFirst();
    }

    public CompletableFuture<RecordMetadata> dispatchNotificationProto(final org.dependencytrack.proto.notification.v1.Notification notification) {
        if (notification == null) {
            return completedFuture(null);
        }

        final KafkaEvent<?, ?> kafkaEvent = KafkaEventConverter.convert(notification);
        return dispatchAll(List.of(kafkaEvent)).getFirst();
    }

    public List<CompletableFuture<RecordMetadata>> dispatchAllNotificationProtos(final Collection<org.dependencytrack.proto.notification.v1.Notification> notifications) {
        final List<KafkaEvent<?, ?>> kafkaEvents = KafkaEventConverter.convertAllNotificationProtos(notifications);
        return dispatchAll(kafkaEvents);
    }

    public List<CompletableFuture<RecordMetadata>> dispatchAll(final Collection<KafkaEvent<?, ?>> events) {
        if (events == null || events.isEmpty()) {
            return Collections.emptyList();
        }

        final var records = new ArrayList<ProducerRecord<byte[], byte[]>>(events.size());
        for (final KafkaEvent<?, ?> event : events) {
            records.add(convert(event));
        }

        final var futures = new ArrayList<CompletableFuture<RecordMetadata>>(records.size());
        for (final ProducerRecord<byte[], byte[]> record : records) {
            final CompletableFuture<RecordMetadata> future = new CompletableFuture<>();
            final Callback producerCallback = (metadata, exception) -> {
                if (exception != null) {
                    LOGGER.error("Failed to produce record to topic %s".formatted(record.topic()), exception);
                    future.completeExceptionally(exception);
                } else {
                    future.complete(metadata);
                }
            };

            producer.send(record, producerCallback);
            futures.add(future);
        }

        return futures;
    }

    private static <K, V> ProducerRecord<byte[], byte[]> convert(final KafkaEvent<K, V> event) {
        final byte[] keyBytes;
        try (final Serde<K> keySerde = event.topic().keySerde()) {
            keyBytes = keySerde.serializer().serialize(event.topic().name(), event.key());
        }

        final byte[] valueBytes;
        try (final Serde<V> valueSerde = event.topic().valueSerde()) {
            valueBytes = valueSerde.serializer().serialize(event.topic().name(), event.value());
        }

        final var record = new ProducerRecord<>(event.topic().name(), keyBytes, valueBytes);
        if (event.headers() != null) {
            for (final Map.Entry<String, String> header : event.headers().entrySet()) {
                record.headers().add(header.getKey(), header.getValue().getBytes(StandardCharsets.UTF_8));
            }
        }

        return record;
    }
}