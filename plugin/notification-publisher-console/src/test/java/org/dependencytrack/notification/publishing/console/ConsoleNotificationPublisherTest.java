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

import org.dependencytrack.notification.publishing.testing.AbstractNotificationPublisherTest;
import org.dependencytrack.plugin.api.notification.publishing.MutableNotificationRuleConfig;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisherFactory;

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
    protected void validateBomConsumedNotificationPublish() {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 1970-01-01T18:31:06.000Z
                  -- level:     LEVEL_INFORMATIONAL
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_BOM_CONSUMED
                  -- title:     Bill of Materials Consumed
                  -- content:   A CycloneDX BOM was consumed and will be processed
                """);
    }

    @Override
    protected void validateBomProcessingFailedNotificationPublish() {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 1970-01-01T18:31:06.000Z
                  -- level:     LEVEL_ERROR
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_BOM_PROCESSING_FAILED
                  -- title:     Bill of Materials Processing Failed
                  -- content:   An error occurred while processing a BOM
                """);
    }

    @Override
    protected void validateBomValidationFailedNotificationPublish() {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 1970-01-01T18:31:06.000Z
                  -- level:     LEVEL_ERROR
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_BOM_VALIDATION_FAILED
                  -- title:     Bill of Materials Validation Failed
                  -- content:   An error occurred while validating a BOM
                """);
    }

    @Override
    protected void validateDataSourceMirroringNotificationPublish() {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 1970-01-01T18:31:06.000Z
                  -- level:     LEVEL_ERROR
                  -- scope:     SCOPE_SYSTEM
                  -- group:     GROUP_DATASOURCE_MIRRORING
                  -- title:     GitHub Advisory Mirroring
                  -- content:   An error occurred mirroring the contents of GitHub Advisories. Check log for details.
                """);
    }

    @Override
    protected void validateNewVulnerabilityNotificationPublish() {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 1970-01-01T18:31:06.000Z
                  -- level:     LEVEL_INFORMATIONAL
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_NEW_VULNERABILITY
                  -- title:     New Vulnerability Identified
                  -- content:  \s
                """);
    }

    @Override
    protected void validateNewVulnerableDependencyNotificationPublish() {
        assertThat(outputStream).asString().isEqualTo("""
                --------------------------------------------------------------------------------
                Notification
                  -- timestamp: 1970-01-01T18:31:06.000Z
                  -- level:     LEVEL_INFORMATIONAL
                  -- scope:     SCOPE_PORTFOLIO
                  -- group:     GROUP_NEW_VULNERABLE_DEPENDENCY
                  -- title:     Vulnerable Dependency Introduced
                  -- content:  \s
                """);
    }

}