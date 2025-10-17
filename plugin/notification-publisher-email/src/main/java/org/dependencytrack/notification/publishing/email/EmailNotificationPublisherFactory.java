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
package org.dependencytrack.notification.publishing.email;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.mail.Session;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisherFactory;
import org.jspecify.annotations.NonNull;

import java.time.Duration;
import java.util.List;
import java.util.SequencedCollection;

import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.PASSWORD_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SMTP_FROM_ADDRESS_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SMTP_HOST_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SMTP_PORT_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.SUBJECT_PREFIX_CONFIG;
import static org.dependencytrack.notification.publishing.email.EmailNotificationPublisherRuleConfigs.USERNAME_CONFIG;

/**
 * @since 5.7.0
 */
final class EmailNotificationPublisherFactory implements NotificationPublisherFactory {

    private Cache<@NonNull SessionCacheKey, Session> sessionCache;

    @Override
    public String extensionName() {
        return "email";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return EmailNotificationPublisher.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> ruleConfigs() {
        return List.of(
                SMTP_HOST_CONFIG,
                SMTP_PORT_CONFIG,
                SMTP_FROM_ADDRESS_CONFIG,
                USERNAME_CONFIG,
                PASSWORD_CONFIG,
                SUBJECT_PREFIX_CONFIG);
    }

    @Override
    public void init(final ExtensionContext ctx) {
        sessionCache = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(5))
                .build();
    }

    @Override
    public NotificationPublisher create() {
        return new EmailNotificationPublisher(sessionCache);
    }

    @Override
    public void close() {
        if (sessionCache != null) {
            sessionCache.invalidateAll();
        }
    }

}
