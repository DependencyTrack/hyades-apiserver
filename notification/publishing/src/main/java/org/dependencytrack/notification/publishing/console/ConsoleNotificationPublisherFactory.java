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

import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.jspecify.annotations.Nullable;

import java.io.OutputStream;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class ConsoleNotificationPublisherFactory implements NotificationPublisherFactory {

    private final OutputStream outputStream;
    private @Nullable ConsoleNotificationPublisher publisher;

    ConsoleNotificationPublisherFactory(final OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public ConsoleNotificationPublisherFactory() {
        this(System.out);
    }

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
        publisher = new ConsoleNotificationPublisher(outputStream);
    }

    @Override
    public NotificationPublisher create() {
        requireNonNull(publisher, "publisher must not be null");
        return publisher;
    }

    @Override
    public String defaultTemplateMimeType() {
        return "text/plain";
    }

}
