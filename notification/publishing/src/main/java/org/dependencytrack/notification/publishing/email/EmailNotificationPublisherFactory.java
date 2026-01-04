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
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.publishing.NotificationPublisherFactory.loadDefaultTemplate;

/**
 * @since 5.7.0
 */
public final class EmailNotificationPublisherFactory implements NotificationPublisherFactory {

    private @Nullable Cache<SessionCacheKey, Session> sessionCache;

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
    public void init(ExtensionContext ctx) {
        sessionCache = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(5))
                .build();
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(sessionCache, "sessionCache must not be null");
        return new EmailNotificationPublisher(sessionCache);
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        final var defaultConfig = new EmailNotificationRuleConfig()
                .withSmtpHost("localhost")
                .withSmtpPort(25)
                .withSenderAddress("dependencytrack@localhost")
                .withSubjectPrefix("[Dependency-Track]");

        return new RuntimeConfigSpec(defaultConfig);
    }

    @Override
    public NotificationTemplate defaultTemplate() {
        return new NotificationTemplate(loadDefaultTemplate(extensionClass()), "text/plain");
    }

    @Override
    public void close() {
        if (sessionCache != null) {
            sessionCache.invalidateAll();
        }
    }

}
