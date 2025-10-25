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
package org.dependencytrack.notification;

import alpine.common.metrics.Metrics;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @since 5.7.0
 */
public final class NotificationSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationSubsystemInitializer.class);

    private final Config config = ConfigProvider.getConfig();
    private NotificationDispatcher dispatcher;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Starting notification dispatcher");
        dispatcher = new NotificationDispatcher(
                new KafkaEventDispatcher(),
                Metrics.getRegistry(),
                config.getOptionalValue("notification-dispatcher.poll-interval-ms", long.class).orElse(1000L),
                config.getOptionalValue("notification-dispatcher.batch-size", int.class).orElse(100));
        dispatcher.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (dispatcher != null) {
            LOGGER.info("Stopping notification dispatcher");
            dispatcher.close();
        }
    }
}
