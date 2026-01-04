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
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.api.TestNotificationFactory;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.plugin.PluginManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

class NotificationOutboxRelayTest extends PersistenceCapableTest {

    private DexEngine dexEngineMock;
    private PluginManager pluginManagerMock;
    private NotificationRouter routerMock;
    private NotificationOutboxRelay relay;

    @BeforeEach
    void beforeEach() {
        dexEngineMock = mock(DexEngine.class);
        pluginManagerMock = mock(PluginManager.class);
        routerMock = mock(NotificationRouter.class);
        relay = new NotificationOutboxRelay(
                dexEngineMock,
                pluginManagerMock,
                ignored -> routerMock,
                new SimpleMeterRegistry(),
                /* pollIntervalMillis */ 10,
                /* batchSize */ 10,
                /* largeNotificationThresholdBytes */ 128 * 1024);
    }

    @AfterEach
    void afterEach() {
        if (relay != null) {
            relay.close();
        }
    }

    @Test
    void shouldRelayNotification() {
        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        createMatchingRule(notification);

        new JdoNotificationEmitter(qm).emit(notification);

        doReturn(List.of(new NotificationRouter.Result(notification, Set.of("ruleName"))))
                .when(routerMock).route(anyCollection());

        relay.start();

        //noinspection unchecked
        final ArgumentCaptor<Collection<CreateWorkflowRunRequest<?>>> createRunsCaptor =
                ArgumentCaptor.forClass(Collection.class);

        await("Kafka producer send completion")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> Mockito.verify(dexEngineMock).createRuns(createRunsCaptor.capture()));

        assertThat(createRunsCaptor.getValue()).satisfiesExactly(request -> {
            assertThat(request.workflowName()).isEqualTo("publish-notification");
            assertThat(request.workflowVersion()).isEqualTo(1);
        });

        await("Outbox record removal")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(qm.getNotificationOutbox()).isEmpty());
    }

    @Test
    void shouldRetryOnFailedSend() {
        final Notification notification = TestNotificationFactory.createBomConsumedTestNotification();

        createMatchingRule(notification);

        new JdoNotificationEmitter(qm).emit(notification);

        doReturn(List.of(new NotificationRouter.Result(notification, Set.of("ruleName"))))
                .when(routerMock).route(anyCollection());

        relay.start();

        doThrow(new IllegalStateException("Boom!"))
                .doReturn(List.of(UUID.fromString("2777be5d-5a95-40b3-9226-311874a21bf6")))
                .when(dexEngineMock).createRuns(anyCollection());

        //noinspection unchecked
        final ArgumentCaptor<Collection<CreateWorkflowRunRequest<?>>> requestsCaptor =
                ArgumentCaptor.forClass(Collection.class);

        await("Kafka producer send completion")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> Mockito.verify(dexEngineMock, times(2)).createRuns(requestsCaptor.capture()));

        assertThat(requestsCaptor.getAllValues())
                .hasSizeGreaterThanOrEqualTo(2)
                .allSatisfy(requests -> {
                    assertThat(requests).satisfiesExactly(request -> {
                        assertThat(request.workflowName()).isEqualTo("publish-notification");
                        assertThat(request.workflowVersion()).isEqualTo(1);
                    });
                });

        await("Outbox record removal")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(qm.getNotificationOutbox()).isEmpty());
    }

    @Nested
    class ConstructorTest {

        @Test
        void shouldThrowWhenDexEngineIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationOutboxRelay(
                            null,
                            pluginManagerMock,
                            ignored -> routerMock,
                            new SimpleMeterRegistry(),
                            /* pollIntervalMillis */ 100,
                            /* batchSize */ 10,
                            /* largeNotificationThresholdBytes */ 128 * 1024));
        }

        @Test
        void shouldThrowWhenPluginManagerIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationOutboxRelay(
                            dexEngineMock,
                            null,
                            ignored -> routerMock,
                            new SimpleMeterRegistry(),
                            /* pollIntervalMillis */ 100,
                            /* batchSize */ 10,
                            /* largeNotificationThresholdBytes */ 128 * 1024));
        }

        @Test
        void shouldThrowWhenRouterFactoryIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationOutboxRelay(
                            dexEngineMock,
                            pluginManagerMock,
                            null,
                            new SimpleMeterRegistry(),
                            /* pollIntervalMillis */ 100,
                            /* batchSize */ 10,
                            /* largeNotificationThresholdBytes */ 128 * 1024));
        }

        @Test
        void shouldThrowWhenMeterRegistryIsNull() {
            assertThatExceptionOfType(NullPointerException.class)
                    .isThrownBy(() -> new NotificationOutboxRelay(
                            dexEngineMock,
                            pluginManagerMock,
                            ignored -> routerMock,
                            null,
                            /* pollIntervalMillis */ 100,
                            /* batchSize */ 10,
                            /* largeNotificationThresholdBytes */ 128 * 1024));
        }

        @Test
        void shouldThrowWhenPollIntervalIsZero() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> new NotificationOutboxRelay(
                            dexEngineMock,
                            pluginManagerMock,
                            ignored -> routerMock,
                            new SimpleMeterRegistry(),
                            /* pollIntervalMillis */ 0,
                            /* batchSize */ 10,
                            /* largeNotificationThresholdBytes */ 128 * 1024));
        }

        @Test
        void shouldThrowWhenBatchSizeIsZero() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> new NotificationOutboxRelay(
                            dexEngineMock,
                            pluginManagerMock,
                            ignored -> routerMock,
                            new SimpleMeterRegistry(),
                            /* pollIntervalMillis */ 100,
                            /* batchSize */ 0,
                            /* largeNotificationThresholdBytes */ 128 * 1024));
        }

    }

    @Test
    void startShouldThrowWhenCalledMultipleTimes() {
        assertThatNoException().isThrownBy(() -> relay.start());

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> relay.start())
                .withMessage("Already started");
    }

    private void createMatchingRule(Notification notification) {
        qm.runInTransaction(() -> {
            final NotificationPublisher publisher = qm.createNotificationPublisher(
                    "publisherName", "description", "extensionName", "templateContent", "templateMimeType", false);
            final NotificationRule rule = qm.createNotificationRule(
                    "ruleName",
                    NotificationModelConverter.convert(notification.getScope()),
                    NotificationModelConverter.convert(notification.getLevel()),
                    publisher);
            rule.setNotifyOn(Set.of(NotificationModelConverter.convert(notification.getGroup())));
        });
    }

}