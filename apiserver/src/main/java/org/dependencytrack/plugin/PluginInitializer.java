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
package org.dependencytrack.plugin;

import alpine.common.logging.Logger;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 * @since 5.6.0
 */
public class PluginInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(PluginInitializer.class);

    private final PluginManager pluginManager = PluginManager.getInstance();

    private final Config config = ConfigProvider.getConfig();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Loading plugins");

        if (!config.getValue("plugin.external.load.enabled", boolean.class)) {
            pluginManager.setExternalPluginConfig(true, config.getValue("plugin.external.dir", String.class));
        }

        pluginManager.loadPlugins();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Unloading plugins");
        pluginManager.unloadPlugins();
    }

}
