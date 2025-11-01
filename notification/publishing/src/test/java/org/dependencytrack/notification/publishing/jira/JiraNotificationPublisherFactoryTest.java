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
package org.dependencytrack.notification.publishing.jira;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JiraNotificationPublisherFactoryTest {

    @Test
    void extensionNameShouldReturnJira() {
        try (final var publisherFactory = new JiraNotificationPublisherFactory()) {
            assertThat(publisherFactory.extensionName()).isEqualTo("jira");
        }
    }

    @Test
    void extensionClassShouldReturnPublisherClass() {
        try (final var publisherFactory = new JiraNotificationPublisherFactory()) {
            assertThat(publisherFactory.extensionClass()).isEqualTo(JiraNotificationPublisher.class);
        }
    }

    @Test
    void priorityShouldReturnZero() {
        try (final var publisherFactory = new JiraNotificationPublisherFactory()) {
            assertThat(publisherFactory.priority()).isZero();
        }
    }

    @Test
    void defaultTemplateShouldNotReturnNull() {
        try (final var publisherFactory = new JiraNotificationPublisherFactory()) {
            assertThat(publisherFactory.defaultTemplate()).isNotNull();
        }
    }

}