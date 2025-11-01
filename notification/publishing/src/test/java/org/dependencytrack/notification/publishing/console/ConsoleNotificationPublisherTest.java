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
package org.dependencytrack.notification.publishing.console;

import org.dependencytrack.notification.api.publishing.MutableNotificationRuleConfig;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.AbstractNotificationPublisherTest;

import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class ConsoleNotificationPublisherTest extends AbstractNotificationPublisherTest {

    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    @Override
    protected NotificationPublisherFactory createPublisherFactory() {
        return new ConsoleNotificationPublisherFactory(outputStream);
    }

    @Override
    protected void customizeRuleConfig(final MutableNotificationRuleConfig ruleConfig) {
    }

    @Override
    protected String getDestination() {
        return null;
    }

    @Override
    protected void validateBomConsumedNotificationPublish(final Notification ignored) {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 2006-06-06T06:06:06.666Z
                  -- level:     LEVEL_INFORMATIONAL
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_BOM_CONSUMED
                  -- title:     Bill of Materials Consumed
                  -- content:   A CycloneDX BOM was consumed and will be processed
                """);
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish(final Notification ignored) {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 2006-06-06T06:06:06.666Z
                  -- level:     LEVEL_ERROR
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_BOM_PROCESSING_FAILED
                  -- title:     Bill of Materials Processing Failed
                  -- content:   An error occurred while processing a BOM
                """);
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish(final Notification ignored) {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 2006-06-06T06:06:06.666Z
                  -- level:     LEVEL_ERROR
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_BOM_VALIDATION_FAILED
                  -- title:     Bill of Materials Validation Failed
                  -- content:   An error occurred while validating a BOM
                """);
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish(final Notification ignored) {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 2006-06-06T06:06:06.666Z
                  -- level:     LEVEL_INFORMATIONAL
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_NEW_VULNERABILITY
                  -- title:     New Vulnerability Identified on Project: [projectName : projectVersion]
                  -- content:   vulnerabilityDescription
                """);
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish(final Notification ignored) {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 2006-06-06T06:06:06.666Z
                  -- level:     LEVEL_INFORMATIONAL
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_NEW_VULNERABLE_DEPENDENCY
                  -- title:     Vulnerable Dependency Introduced on Project: [projectName : projectVersion]
                  -- content:   A dependency was introduced that contains 1 known vulnerability
                """);
    }

}