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
package org.dependencytrack.notification.publishing.http;

import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.RenderedNotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public abstract class AbstractHttpNotificationPublisher implements NotificationPublisher {

    private final HttpClient httpClient;
    private final Set<Integer> retryableStatusCodes;
    private final Logger logger;

    protected AbstractHttpNotificationPublisher(HttpClient httpClient) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.retryableStatusCodes = Set.of(429, 503);
        this.logger = LoggerFactory.getLogger(getClass());
    }

    @Override
    public void publish(NotificationPublishContext ctx, Notification notification) throws IOException {
        final var ruleConfig = ctx.ruleConfig(HttpNotificationRuleConfig.class);

        final RenderedNotificationTemplate renderedTemplate = ctx.templateRenderer().render(notification);
        if (renderedTemplate == null) {
            throw new IllegalStateException("No template configured");
        }

        final var request = HttpRequest
                .newBuilder(ruleConfig.getDestinationUrl())
                .header("Content-Type", renderedTemplate.mimeType())
                .POST(HttpRequest.BodyPublishers.ofString(renderedTemplate.content()))
                .timeout(Duration.ofSeconds(10))
                .build();

        final HttpResponse<?> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RetryablePublishException("Interrupted while sending request", e);
        } catch (HttpTimeoutException e) {
            throw new RetryablePublishException("Timed out while sending request", e);
        }

        final int statusCode = response.statusCode();
        if (statusCode < 200 || statusCode > 299) {
            if (!retryableStatusCodes.contains(statusCode)) {
                throw new IllegalStateException("Request failed with unexpected response code: " + statusCode);
            }

            final var message = "Request failed with retryable response code: " + statusCode;

            final String retryAfterHeader = response.headers().firstValue("Retry-After").orElse(null);
            if (retryAfterHeader == null) {
                throw new RetryablePublishException(message);
            }

            final int retryAfterSeconds;
            try {
                retryAfterSeconds = Integer.parseInt(retryAfterHeader);
            } catch (NumberFormatException e) {
                logger.debug("Failed to parse Retry-After header", e);
                throw new RetryablePublishException(message);
            }

            throw new RetryablePublishException(message, Duration.ofSeconds(retryAfterSeconds));
        }
    }

}
