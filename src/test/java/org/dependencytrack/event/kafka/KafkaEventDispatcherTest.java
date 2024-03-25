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

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.junit.Before;
import org.junit.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class KafkaEventDispatcherTest {

    private MockProducer<byte[], byte[]> mockProducer;

    @Before
    public void setUp() {
        mockProducer = new MockProducer<>(true, new ByteArraySerializer(), new ByteArraySerializer());
    }

    @Test
    public void testDispatchAsyncCallback() throws Exception {
        final var component = new Component();
        component.setUuid(UUID.randomUUID());
        component.setName("foobar");

        final var event = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS, false);
        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        final var countDownLatch = new CountDownLatch(1);
        dispatcher.dispatchAsync(event, (metadata, exception) -> countDownLatch.countDown());
        assertThat(countDownLatch.await(5, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    public void testDispatchBlocking() {
        final var component = new Component();
        component.setUuid(UUID.randomUUID());
        component.setName("foobar");

        final var event = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS, false);

        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        final RecordMetadata recordMeta = dispatcher.dispatchBlocking(event);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.VULN_ANALYSIS_COMMAND.name());
        assertThat(mockProducer.history()).hasSize(1);
    }

    @Test
    public void testDispatchBlockingMirrorEvents() {
        final var eventOsv = new OsvMirrorEvent("npm");
        var dispatcher = new KafkaEventDispatcher(mockProducer);
        RecordMetadata recordMeta = dispatcher.dispatchBlocking(eventOsv);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.VULNERABILITY_MIRROR_COMMAND.name());
        assertThat(mockProducer.history()).hasSize(1);

        final var eventNvd = new NistMirrorEvent();
        dispatcher = new KafkaEventDispatcher(mockProducer);
        recordMeta = dispatcher.dispatchBlocking(eventNvd);
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.VULNERABILITY_MIRROR_COMMAND.name());
        assertThat(mockProducer.history()).hasSize(2);
    }

    @Test
    public void testDispatchAsyncWithUnsupportedEvent() {
        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dispatcher.dispatchAsync(new PortfolioMetricsUpdateEvent()));
        assertThat(mockProducer.history()).isEmpty();
    }

    @Test
    public void testDispatchAsyncNotification() throws Exception {
        final var notification = new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABILITY)
                .level(NotificationLevel.INFORMATIONAL);

        final var dispatcher = new KafkaEventDispatcher(mockProducer);
        final RecordMetadata recordMeta = dispatcher.dispatchAsync(UUID.randomUUID(), notification).get();
        assertThat(recordMeta.topic()).isEqualTo(KafkaTopics.NOTIFICATION_NEW_VULNERABILITY.name());
        assertThat(mockProducer.history()).hasSize(1);
    }
}