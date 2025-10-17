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
package org.dependencytrack.notification.publishing;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplateRenderer;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomConsumedTestNotification;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomProcessingFailedTestNotification;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomValidationFailedTestNotification;
import static org.dependencytrack.notification.api.TestNotificationFactory.createNewVulnerabilityTestNotification;
import static org.dependencytrack.notification.api.TestNotificationFactory.createNewVulnerableDependencyTestNotification;

public abstract class AbstractNotificationPublisherTest {

    private static final String NOTIFICATION_ID = "010ba7f2-ab4a-73b6-a87d-7b9041d17016";
    private static final Timestamp NOTIFICATION_TIMESTAMP = Timestamps.fromMillis(1149573966666L);

    protected NotificationPublisherFactory publisherFactory;
    protected NotificationPublisher publisher;
    protected NotificationPublishContext publishContext;

    protected abstract NotificationPublisherFactory createPublisherFactory();

    protected void customizeRuleConfig(RuntimeConfig ruleConfig) {
    }

    @BeforeEach
    protected void beforeEach() throws Exception {
        publisherFactory = createPublisherFactory();
        publisherFactory.init(new ExtensionContext(new MockConfigRegistry()));
        publisher = publisherFactory.create();

        final var templateRendererFactory =
                new PebbleNotificationTemplateRendererFactory(
                        Map.of("baseUrl", () -> "https://example.com"));
        final NotificationTemplateRenderer templateRenderer =
                templateRendererFactory.createRenderer(
                        publisherFactory.defaultTemplate());

        RuntimeConfig ruleConfig = null;

        final RuntimeConfigSpec ruleConfigSpec = publisherFactory.ruleConfigSpec();
        if (ruleConfigSpec != null) {
            ruleConfig = ruleConfigSpec.defaultConfig();
            customizeRuleConfig(ruleConfig);
        }

        publishContext = new NotificationPublishContext(ruleConfig, templateRenderer);
    }

    @AfterEach
    protected void afterEach() {
        if (publisher != null) {
            publisher.close();
        }
        if (publisherFactory != null) {
            publisherFactory.close();
        }
    }

    protected abstract void validateBomConsumedNotificationPublish(Notification notification) throws Exception;

    @Test
    void shouldPublishBomConsumedNotification() throws Exception {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .setId(NOTIFICATION_ID)
                        .setTimestamp(NOTIFICATION_TIMESTAMP)
                        .build();

        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        validateBomConsumedNotificationPublish(notification);
    }

    protected abstract void validateBomProcessingFailedNotificationPublish(Notification notification) throws Exception;

    @Test
    void shouldPublishBomProcessingFailedNotification() throws Exception {
        final Notification notification =
                createBomProcessingFailedTestNotification().toBuilder()
                        .setId(NOTIFICATION_ID)
                        .setTimestamp(NOTIFICATION_TIMESTAMP)
                        .build();

        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        validateBomProcessingFailedNotificationPublish(notification);
    }

    protected abstract void validateBomValidationFailedNotificationPublish(Notification notification) throws Exception;

    @Test
    void shouldPublishBomValidationFailedNotification() throws Exception {
        final Notification notification =
                createBomValidationFailedTestNotification().toBuilder()
                        .setId(NOTIFICATION_ID)
                        .setTimestamp(NOTIFICATION_TIMESTAMP)
                        .build();

        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        validateBomValidationFailedNotificationPublish(notification);
    }

    protected abstract void validateNewVulnerabilityNotificationPublish(Notification notification) throws Exception;

    @Test
    void shouldPublishNewVulnerabilityNotification() throws Exception {
        final Notification notification =
                createNewVulnerabilityTestNotification().toBuilder()
                        .setId(NOTIFICATION_ID)
                        .setTimestamp(NOTIFICATION_TIMESTAMP)
                        .build();

        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        validateNewVulnerabilityNotificationPublish(notification);
    }

    protected abstract void validateNewVulnerableDependencyNotificationPublish(Notification notification) throws Exception;

    @Test
    void shouldPublishNewVulnerableDependencyNotification() throws Exception {
        final Notification notification =
                createNewVulnerableDependencyTestNotification().toBuilder()
                        .setId(NOTIFICATION_ID)
                        .setTimestamp(NOTIFICATION_TIMESTAMP)
                        .build();

        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, notification));

        validateNewVulnerableDependencyNotificationPublish(notification);
    }

}
