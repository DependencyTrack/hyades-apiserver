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

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;

/**
 * @since 5.6.0
 */
public final class InitTaskServletContextListener implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(InitTaskServletContextListener.class);

    private final Config config;
    private final DataSourceRegistry dataSourceRegistry;

    @SuppressWarnings("unused")
    public InitTaskServletContextListener() {
        this(ConfigProvider.getConfig(), DataSourceRegistry.getInstance());
    }

    InitTaskServletContextListener(
            final Config config,
            final DataSourceRegistry dataSourceRegistry) {
        this.config = config;
        this.dataSourceRegistry = dataSourceRegistry;
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getValue(ConfigKey.INIT_TASKS_ENABLED.getPropertyName(), Boolean.class)) {
            LOGGER.debug(
                    "Not executing init tasks because {} is disabled",
                    ConfigKey.INIT_TASKS_ENABLED.getPropertyName());
            return;
        }

        final String dataSourceName = config.getValue("init.tasks.datasource.name", String.class);
        final DataSource dataSource = dataSourceRegistry.get(dataSourceName);

        final var taskExecutor = new InitTaskExecutor(config, dataSource);
        taskExecutor.execute();

        if (config.getValue("init.tasks.datasource.close-after-use", boolean.class)) {
            dataSourceRegistry.close(dataSourceName);
        }

        if (config.getValue(ConfigKey.INIT_AND_EXIT.getPropertyName(), Boolean.class)) {
            LOGGER.info(
                    "Exiting because {} is enabled",
                    ConfigKey.INIT_AND_EXIT.getPropertyName());
            System.exit(0);
        }
    }

}
