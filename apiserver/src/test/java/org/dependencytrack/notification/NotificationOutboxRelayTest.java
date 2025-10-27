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
package org.dependencytrack.notification;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.proto.notification.v1.Notification;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.util.KafkaTestUtil.deserializeKey;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class NotificationOutboxRelayTest extends PersistenceCapableTest {

    private MockProducer<byte[], byte[]> mockProducer;
    private NotificationOutboxRelay relay;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        mockProducer = new MockProducer<>(
                /* autoComplete */ false,
                new ByteArraySerializer(),
                new ByteArraySerializer());
        relay = new NotificationOutboxRelay(
                new KafkaEventDispatcher(mockProducer),
                new SimpleMeterRegistry(),
                /* routerEnabled */ true,
                /* pollIntervalMillis */ 10,
                /* batchSize */ 10);
    }

    @Override
    public void after() {
        if (relay != null) {
            relay.close();
        }
        if (mockProducer != null) {
            mockProducer.close();
        }

        super.after();
    }

    @Test
    public void shouldRelayNotification() {
        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        NotificationEmitter.using(qm).emit(notification);

        relay.start();

        await("Kafka producer send completion")
                .atMost(1, TimeUnit.SECONDS)
                .until(() -> mockProducer.completeNext());

        assertThat(mockProducer.history()).satisfiesExactly(record -> {
            final String key = deserializeKey(
                    KafkaTopics.NOTIFICATION_BOM, record);
            assertThat(key).isEqualTo("c9c9539a-e381-4b36-ac52-6a7ab83b2c95");

            final Notification value = deserializeValue(
                    KafkaTopics.NOTIFICATION_BOM, record);
            assertThat(value).isEqualTo(notification);
        });

        await("Outbox record removal")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(qm.getNotificationOutbox()).isEmpty());
    }

    @Test
    public void shouldRetryOnFailedSend() {
        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        NotificationEmitter.using(qm).emit(notification);

        relay.start();

        await("Kafka producer send failure")
                .atMost(1, TimeUnit.SECONDS)
                .until(() -> mockProducer.errorNext(new IllegalStateException("Boom!")));

        assertThat(qm.getNotificationOutbox()).hasSize(1);

        await("Kafka producer send completion")
                .atMost(1, TimeUnit.SECONDS)
                .until(() -> mockProducer.completeNext());

        // Mock producer keeps all records in its history,
        // even if delivery of them failed.
        assertThat(mockProducer.history())
                .hasSizeGreaterThanOrEqualTo(2)
                .anySatisfy(record -> {
                    final String key = deserializeKey(
                            KafkaTopics.NOTIFICATION_BOM, record);
                    assertThat(key).isEqualTo("c9c9539a-e381-4b36-ac52-6a7ab83b2c95");

                    final Notification value = deserializeValue(
                            KafkaTopics.NOTIFICATION_BOM, record);
                    assertThat(value).isEqualTo(notification);
                });

        await("Outbox record removal")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(qm.getNotificationOutbox()).isEmpty());
    }

    @Test
    @SuppressWarnings("resource")
    public void constructorShouldThrowWhenDelegateDispatcherIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new NotificationOutboxRelay(
                        null,
                        new SimpleMeterRegistry(),
                        true,
                        100,
                        10));
    }

    @Test
    @SuppressWarnings("resource")
    public void constructorShouldThrowWhenMeterRegistryIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new NotificationOutboxRelay(
                        new KafkaEventDispatcher(mockProducer),
                        null,
                        true,
                        100,
                        10));
    }

    @Test
    @SuppressWarnings("resource")
    public void constructorShouldThrowWhenPollIntervalIsZero() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new NotificationOutboxRelay(
                        new KafkaEventDispatcher(mockProducer),
                        new SimpleMeterRegistry(),
                        true,
                        0,
                        10));
    }

    @Test
    @SuppressWarnings("resource")
    public void constructorShouldThrowWhenBatchSizeIsZero() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new NotificationOutboxRelay(
                        new KafkaEventDispatcher(mockProducer),
                        new SimpleMeterRegistry(),
                        true,
                        100,
                        0));
    }

    @Test
    public void startShouldThrowWhenCalledMultipleTimes() {
        assertThatNoException().isThrownBy(() -> relay.start());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> relay.start())
                .withMessage("Already started");
    }

}