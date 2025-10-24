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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisherFactory;

import java.net.http.HttpClient;
import java.util.List;
import java.util.SequencedCollection;

import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.PASSWORD_OR_TOKEN_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.PROJECT_KEY_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.TICKET_TYPE_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.USERNAME_CONFIG;

/**
 * @since 5.7.0
 */
final class JiraNotificationPublisherFactory implements NotificationPublisherFactory {

    private HttpClient httpClient;

    @Override
    public String extensionName() {
        return "jira";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return JiraNotificationPublisher.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public SequencedCollection<RuntimeConfigDefinition<?>> ruleConfigs() {
        return List.of(
                USERNAME_CONFIG,
                PASSWORD_OR_TOKEN_CONFIG,
                PROJECT_KEY_CONFIG,
                TICKET_TYPE_CONFIG);
    }

    @Override
    public void init(final ExtensionContext ctx) {
        httpClient = HttpClient.newBuilder()
                .proxy(ctx.proxySelector())
                .build();
    }

    @Override
    public NotificationPublisher create() {
        return new JiraNotificationPublisher(httpClient);
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.close();
        }
    }

}
