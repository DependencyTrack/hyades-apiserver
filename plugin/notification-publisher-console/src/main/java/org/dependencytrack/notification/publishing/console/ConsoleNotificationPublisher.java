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

import org.dependencytrack.plugin.api.notification.publishing.NotificationPublisher;
import org.dependencytrack.plugin.api.notification.publishing.PublishContext;
import org.dependencytrack.proto.notification.v1.Notification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @since 5.7.0
 */
final class ConsoleNotificationPublisher implements NotificationPublisher {

    private final Logger logger;

    ConsoleNotificationPublisher(final Logger logger) {
        this.logger = logger;
    }

    ConsoleNotificationPublisher() {
        this(LoggerFactory.getLogger(ConsoleNotificationPublisher.class));
    }

    @Override
    public void publish(final PublishContext ctx, final Notification notification) {
        logger.info(new String(ctx.templateRenderer().render(notification)));
    }

}
