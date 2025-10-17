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
package org.dependencytrack.notification.publishing.msteams;

import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.publishing.http.HttpNotificationRuleConfig;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.http.HttpClient;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.publishing.NotificationPublisherFactory.loadDefaultTemplate;

/**
 * @since 5.7.0
 */
public final class MsTeamsNotificationPublisherFactory implements NotificationPublisherFactory {

    private @Nullable HttpClient httpClient;

    @Override
    public String extensionName() {
        return "msteams";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return MsTeamsNotificationPublisher.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void init(ExtensionContext ctx) {
        this.httpClient = HttpClient.newBuilder()
                .proxy(ctx.proxySelector())
                .build();
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(httpClient, "httpClient must not be null");
        return new MsTeamsNotificationPublisher(httpClient);
    }

    @Override
    public RuntimeConfigSpec ruleConfigSpec() {
        final var defaultConfig = new HttpNotificationRuleConfig()
                .withDestinationUrl(URI.create("https://msteams.example.com"));

        return new RuntimeConfigSpec(defaultConfig);
    }

    @Override
    public NotificationTemplate defaultTemplate() {
        return new NotificationTemplate(loadDefaultTemplate(extensionClass()), "application/json");
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

}
