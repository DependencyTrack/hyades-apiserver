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

import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.PublishContext;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedTemplate;
import org.dependencytrack.notification.proto.v1.Notification;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.PASSWORD_OR_TOKEN_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.PROJECT_KEY_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.TICKET_TYPE_CONFIG;
import static org.dependencytrack.notification.publishing.jira.JiraNotificationPublisherRuleConfigs.USERNAME_CONFIG;

/**
 * @since 5.7.0
 */
final class JiraNotificationPublisher implements NotificationPublisher {

    private final HttpClient httpClient;

    JiraNotificationPublisher(final HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public void publish(final PublishContext ctx, final Notification notification) throws IOException {
        final String apiUrl = requireNonNull(ctx.destination(), "destination must not be null");
        final String username = ctx.ruleConfig().getOptionalValue(USERNAME_CONFIG).orElse(null);
        final String passwordOrToken = ctx.ruleConfig().getValue(PASSWORD_OR_TOKEN_CONFIG);
        final String projectKey = ctx.ruleConfig().getValue(PROJECT_KEY_CONFIG);
        final String ticketType = ctx.ruleConfig().getValue(TICKET_TYPE_CONFIG);

        final RenderedTemplate renderedTemplate = ctx.templateRenderer().render(
                notification,
                Map.ofEntries(
                        Map.entry("jiraProjectKey", projectKey),
                        Map.entry("jiraTicketType", ticketType)));
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        final String authHeader;
        if (username != null) {
            final var credentials = Base64.getEncoder().encodeToString(
                    "%s:%s".formatted(username, passwordOrToken).getBytes());
            authHeader = "Basic " + credentials;
        } else {
            authHeader = "Bearer " + passwordOrToken;
        }

        final var request = HttpRequest.newBuilder()
                .uri(URI.create("%s/rest/api/2/issue".formatted(apiUrl)))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(renderedTemplate.content()))
                .build();

        final HttpResponse<?> response;
        try {
            response = httpClient.send(
                    request, HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending request", e);
        }

        if (response.statusCode() != 201) {
            throw new IllegalStateException("Unexpected response code " + response.statusCode());
        }
    }

}
