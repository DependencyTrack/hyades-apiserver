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
package org.dependencytrack.notification.publishing.testing;

import org.dependencytrack.notification.templating.pebble.PebbleTemplateRenderer;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.dependencytrack.plugin.api.notification.publishing.MutableNotificationRuleConfig;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisherFactory;
import org.dependencytrack.plugin.api.notification.publishing.PublishContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.notification.publishing.testing.NotificationFixtures.BOM_CONSUMED_NOTIFICATION;
import static org.dependencytrack.notification.publishing.testing.NotificationFixtures.BOM_PROCESSING_FAILED_NOTIFICATION;
import static org.dependencytrack.notification.publishing.testing.NotificationFixtures.BOM_VALIDATION_FAILED_NOTIFICATION;
import static org.dependencytrack.notification.publishing.testing.NotificationFixtures.DATA_SOURCE_MIRRORING_NOTIFICATION;
import static org.dependencytrack.notification.publishing.testing.NotificationFixtures.NEW_VULNERABILITY_NOTIFICATION;
import static org.dependencytrack.notification.publishing.testing.NotificationFixtures.NEW_VULNERABLE_DEPENDENCY_NOTIFICATION;

/**
 * @since 5.7.0
 */
public abstract class AbstractNotificationPublisherTest {

    protected NotificationPublisherFactory publisherFactory;
    protected NotificationPublisher publisher;
    protected PublishContext publishContext;

    protected abstract NotificationPublisherFactory createPublisherFactory();

    protected abstract void customizeRuleConfig(final MutableNotificationRuleConfig ruleConfig);

    protected abstract String getDestination();

    @BeforeEach
    protected void beforeEach() throws Exception {
        publisherFactory = createPublisherFactory();
        publisherFactory.init(new ExtensionContext(new MockConfigRegistry()));
        publisher = publisherFactory.create();

        final var templateRenderer = new PebbleTemplateRenderer(Map.ofEntries(
                Map.entry("baseUrl", () -> "https://example.com")));

        final var ruleConfig = MutableNotificationRuleConfig.ofDefaults(publisherFactory);
        customizeRuleConfig(ruleConfig);

        publishContext = new PublishContext(
                getDestination(),
                publisherFactory.defaultTemplate(),
                null,
                templateRenderer,
                ruleConfig);
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

    protected abstract void validateBomConsumedNotificationPublish();

    @Test
    void shouldPublishBomConsumedNotification() {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, BOM_CONSUMED_NOTIFICATION));

        validateBomConsumedNotificationPublish();
    }

    protected abstract void validateBomProcessingFailedNotificationPublish();

    @Test
    void shouldPublishBomProcessingFailedNotification() {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, BOM_PROCESSING_FAILED_NOTIFICATION));

        validateBomProcessingFailedNotificationPublish();
    }

    protected abstract void validateBomValidationFailedNotificationPublish();

    @Test
    void shouldPublishBomValidationFailedNotification() {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, BOM_VALIDATION_FAILED_NOTIFICATION));

        validateBomValidationFailedNotificationPublish();
    }

    protected abstract void validateDataSourceMirroringNotificationPublish();

    @Test
    void shouldPublishDataSourceMirroringNotification() {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, DATA_SOURCE_MIRRORING_NOTIFICATION));

        validateDataSourceMirroringNotificationPublish();
    }

    protected abstract void validateNewVulnerabilityNotificationPublish();

    @Test
    void shouldPublishNewVulnerabilityNotification() {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, NEW_VULNERABILITY_NOTIFICATION));

        validateNewVulnerabilityNotificationPublish();
    }

    protected abstract void validateNewVulnerableDependencyNotificationPublish();

    @Test
    void shouldPublishNewVulnerableDependencyNotification() {
        assertThatNoException()
                .isThrownBy(() -> publisher.publish(publishContext, NEW_VULNERABLE_DEPENDENCY_NOTIFICATION));

        validateNewVulnerableDependencyNotificationPublish();
    }

}
