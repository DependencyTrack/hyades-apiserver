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
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.proto.notification.v1.Notification;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.util.KafkaTestUtil.deserializeKey;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class NotificationDispatcherTest extends PersistenceCapableTest {

    private MockProducer<byte[], byte[]> mockProducer;
    private NotificationDispatcher dispatcher;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        mockProducer = new MockProducer<>(
                true, new ByteArraySerializer(), new ByteArraySerializer());
        dispatcher = new NotificationDispatcher(
                new KafkaEventDispatcher(mockProducer),
                new SimpleMeterRegistry(),
                /* pollIntervalMillis */ 100,
                /* batchSize */ 10);
    }

    @Override
    public void after() {
        if (dispatcher != null) {
            dispatcher.close();
        }
        if (mockProducer != null) {
            mockProducer.close();
        }

        super.after();
    }

    @Test
    public void shouldDispatchNotification() {
        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        NotificationEmitter.using(qm).emit(notification);

        dispatcher.start();

        final List<ProducerRecord<byte[], byte[]>> kafkaRecords =
                await("Notification dispatch")
                        .atMost(5, TimeUnit.SECONDS)
                        .until(() -> mockProducer.history(), history -> history.size() == 1);

        assertThat(kafkaRecords).satisfiesExactly(record -> {
            final String key = deserializeKey(
                    KafkaTopics.NOTIFICATION_BOM, record);
            assertThat(key).isEqualTo("c9c9539a-e381-4b36-ac52-6a7ab83b2c95");

            final Notification value = deserializeValue(
                    KafkaTopics.NOTIFICATION_BOM, record);
            assertThat(value).isEqualTo(notification);
        });

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    public void shouldThrowWhenStartIsCalledMultipleTimes() {
        assertThatNoException().isThrownBy(() -> dispatcher.start());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> dispatcher.start())
                .withMessage("Already started");
    }

}