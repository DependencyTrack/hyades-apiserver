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

import io.micrometer.core.instrument.Metrics;
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
    private NotificationOutboxRelay relay;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getValue("notification.outbox-relay.enabled", boolean.class)) {
            LOGGER.info("Not starting outbox relay because it is disabled");
            return;
        }

        LOGGER.info("Starting outbox relay");
        relay = new NotificationOutboxRelay(
                new KafkaEventDispatcher(),
                Metrics.globalRegistry,
                config.getValue("notification.router.enabled", boolean.class),
                config.getValue("notification.outbox-relay.poll-interval-ms", long.class),
                config.getValue("notification.outbox-relay.batch-size", int.class));
        relay.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (relay != null) {
            LOGGER.info("Stopping outbox relay");
            relay.close();
        }
    }
}
