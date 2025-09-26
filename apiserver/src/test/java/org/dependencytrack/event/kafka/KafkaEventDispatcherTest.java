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
import org.dependencytrack.event.ComponentRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class KafkaEventDispatcherTest {

    private MockProducer<byte[], byte[]> mockProducer;
    private KafkaEventDispatcher eventDispatcher;

    @Before
    public void setUp() {
        mockProducer = new MockProducer<>(false, new ByteArraySerializer(), new ByteArraySerializer());
        eventDispatcher = new KafkaEventDispatcher(mockProducer);
    }

    @Test
    public void testDispatchEventWithNull() {
        final CompletableFuture<RecordMetadata> future = eventDispatcher.dispatchEvent(null);
        assertThat(mockProducer.completeNext()).isFalse();
        assertThat(future).isCompletedWithValue(null);
    }

    @Test
    public void testDispatchEventWithComponentRepositoryMetaAnalysisEvent() {
        final var event = new ComponentRepositoryMetaAnalysisEvent(UUID.randomUUID(),
                "pkg:maven/foo/bar@1.2.3", /* internal */ false, FetchMeta.FETCH_META_LATEST_VERSION);
        final CompletableFuture<RecordMetadata> future = eventDispatcher.dispatchEvent(event);
        assertThat(mockProducer.completeNext()).isTrue();
        assertThat(future).isCompletedWithValueMatching(Objects::nonNull);

        assertThat(mockProducer.history()).satisfiesExactly(record -> {
            assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
            assertThat(record.key()).asString().isEqualTo("pkg:maven/foo/bar@1.2.3");
            assertThat(record.value()).isNotNull();
            assertThat(record.headers()).isEmpty();
        });
    }

    @Test
    public void testDispatchEventWithComponentVulnerabilityAnalysisEvent() {
        final var event = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), UUID.randomUUID(),
                "purl", "cpe", "swidTagId", /* internal */ false,
                VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS, /* isNew */ true);
        final CompletableFuture<RecordMetadata> future = eventDispatcher.dispatchEvent(event);
        assertThat(mockProducer.completeNext()).isTrue();
        assertThat(future).isCompletedWithValueMatching(Objects::nonNull);

        assertThat(mockProducer.history()).satisfiesExactly(record -> {
            assertThat(record.topic()).isEqualTo(KafkaTopics.VULN_ANALYSIS_COMMAND.name());
            assertThat(record.key()).isNotNull();
            assertThat(record.value()).isNotNull();
            assertThat(record.headers()).satisfiesExactlyInAnyOrder(
                    header -> {
                        assertThat(header.key()).isEqualTo(KafkaEventHeaders.VULN_ANALYSIS_LEVEL);
                        assertThat(header.value()).asString().isEqualTo("BOM_UPLOAD_ANALYSIS");
                    },
                    header -> {
                        assertThat(header.key()).isEqualTo(KafkaEventHeaders.IS_NEW_COMPONENT);
                        assertThat(header.value()).asString().isEqualTo("true");
                    }
            );
        });
    }

    @Test
    public void testDispatchEventWithUnsupportedType() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> eventDispatcher.dispatchEvent(new PortfolioMetricsUpdateEvent()))
                .withMessageStartingWith("Unable to convert event");
    }

    @Test
    public void testDispatchNotificationWithNull() {
        final CompletableFuture<RecordMetadata> future = eventDispatcher.dispatchNotification(null);
        assertThat(mockProducer.completeNext()).isFalse();
        assertThat(future).isCompletedWithValue(null);
    }

    @Test
    public void testDispatchNotification() {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.ANALYZER)
                .level(NotificationLevel.ERROR);
        final CompletableFuture<RecordMetadata> future = eventDispatcher.dispatchNotification(notification);
        assertThat(mockProducer.completeNext()).isTrue();
        assertThat(future).isCompletedWithValueMatching(Objects::nonNull);

        assertThat(mockProducer.history()).satisfiesExactly(record -> {
            assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_ANALYZER.name());
            assertThat(record.key()).isNull();
            assertThat(record.value()).isNotNull();
            assertThat(record.headers()).isEmpty();
        });
    }

    @Test
    public void testDispatchNotificationWithoutGroup() {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .level(NotificationLevel.ERROR);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> eventDispatcher.dispatchNotification(notification))
                .withMessage("""
                        Unable to determine destination topic because the notification does not \
                        specify a notification group: GROUP_UNSPECIFIED""");
    }

    @Test
    public void testDispatchNotificationWitMissingSubject() {
        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.BOM_CONSUMED)
                .level(NotificationLevel.INFORMATIONAL);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> eventDispatcher.dispatchNotification(notification))
                .withMessage("""
                        Expected subject of type matching any of [class org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject], \
                        but notification has no subject""");
    }

    @Test
    public void testDispatchNotificationWithSubjectMismatch() {
        final var project = new Project();
        project.setUuid(UUID.randomUUID());
        project.setName("foo");

        final var notification = new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.BOM_CONSUMED)
                .level(NotificationLevel.INFORMATIONAL)
                .subject(project);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> eventDispatcher.dispatchNotification(notification))
                .withMessage("""
                        Expected subject of type matching any of [class org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject], \
                        but is type.googleapis.com/org.dependencytrack.notification.v1.Project""");
    }

    @Test
    public void testDispatchAllNotificationProtosWithEmptyCollection() {
        assertThat(eventDispatcher.dispatchAllNotificationProtos(Collections.emptyList())).isEmpty();
    }

}