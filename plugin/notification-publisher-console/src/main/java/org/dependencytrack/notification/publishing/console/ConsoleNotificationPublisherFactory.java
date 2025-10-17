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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisherFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/**
 * @since 5.7.0
 */
final class ConsoleNotificationPublisherFactory implements NotificationPublisherFactory {

    private ConsoleNotificationPublisher publisher;

    @Override
    public String extensionName() {
        return "console";
    }

    @Override
    public Class<? extends NotificationPublisher> extensionClass() {
        return ConsoleNotificationPublisher.class;
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void init(final ExtensionContext ctx) {
        publisher = new ConsoleNotificationPublisher();
    }

    @Override
    public NotificationPublisher create() {
        return publisher;
    }

    @Override
    public String defaultTemplate() {
        try (final InputStream inputStream = getClass().getResourceAsStream("default-template.peb")) {
            if (inputStream == null) {
                throw new IllegalStateException("Default template could not be found");
            }

            return new String(inputStream.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
