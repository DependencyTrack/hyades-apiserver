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
package org.dependencytrack.notification.publishing.webhook;

import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.PublishContext;
import org.dependencytrack.proto.notification.v1.Notification;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

/**
 * @since 5.7.0
 */
final class WebhookNotificationPublisher implements NotificationPublisher {

    private final HttpClient httpClient;

    WebhookNotificationPublisher(final HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public void publish(final PublishContext ctx, final Notification notification) throws IOException {
        final byte[] content = ctx.templateRenderer().render(notification);
        final String contentMimeType = Optional.ofNullable(ctx.templateMimeType()).orElse("application/json");

        final var request = HttpRequest
                .newBuilder(URI.create(ctx.destination()))
                .header("Content-Type", contentMimeType)
                .POST(HttpRequest.BodyPublishers.ofByteArray(content))
                .build();

        final HttpResponse<?> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (response.statusCode() < 200 || response.statusCode() > 299) {
            throw new IllegalStateException("Unexpected response code: " + response.statusCode());
        }
    }

}
