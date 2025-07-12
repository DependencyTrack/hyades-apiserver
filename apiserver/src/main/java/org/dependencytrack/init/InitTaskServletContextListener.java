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
package org.dependencytrack.init;

import alpine.Config;
import org.dependencytrack.common.ConfigKey;
import org.postgresql.ds.PGSimpleDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import javax.sql.DataSource;

import static alpine.Config.AlpineKey.DATABASE_PASSWORD;
import static alpine.Config.AlpineKey.DATABASE_URL;
import static alpine.Config.AlpineKey.DATABASE_USERNAME;
import static java.util.Objects.requireNonNullElseGet;
import static org.dependencytrack.common.ConfigKey.INIT_TASKS_DATABASE_PASSWORD;
import static org.dependencytrack.common.ConfigKey.INIT_TASKS_DATABASE_URL;
import static org.dependencytrack.common.ConfigKey.INIT_TASKS_DATABASE_USERNAME;

/**
 * @since 5.6.0
 */
public final class InitTaskServletContextListener implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(InitTaskServletContextListener.class);

    private final Config config;

    @SuppressWarnings("unused")
    public InitTaskServletContextListener() {
        this(Config.getInstance());
    }

    InitTaskServletContextListener(final Config config) {
        this.config = config;
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getPropertyAsBoolean(ConfigKey.INIT_TASKS_ENABLED)) {
            LOGGER.debug(
                    "Not executing init tasks because {} is disabled",
                    ConfigKey.INIT_TASKS_ENABLED.getPropertyName());
            return;
        }

        final DataSource dataSource;
        try {
            dataSource = createDataSource(config);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Failed to create data source", e);
        }

        final var taskExecutor = new InitTaskExecutor(config, dataSource);
        taskExecutor.execute();

        if (config.getPropertyAsBoolean(ConfigKey.INIT_AND_EXIT)) {
            LOGGER.info(
                    "Exiting because {} is enabled",
                    ConfigKey.INIT_AND_EXIT.getPropertyName());
            System.exit(0);
        }
    }

    private DataSource createDataSource(final Config config) {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(requireNonNullElseGet(
                config.getProperty(INIT_TASKS_DATABASE_URL),
                () -> config.getProperty(DATABASE_URL)));
        dataSource.setUser(requireNonNullElseGet(
                config.getProperty(INIT_TASKS_DATABASE_USERNAME),
                () -> config.getProperty(DATABASE_USERNAME)));
        dataSource.setPassword(requireNonNullElseGet(
                config.getProperty(INIT_TASKS_DATABASE_PASSWORD),
                () -> config.getPropertyOrFile(DATABASE_PASSWORD)));

        return dataSource;
    }

}
