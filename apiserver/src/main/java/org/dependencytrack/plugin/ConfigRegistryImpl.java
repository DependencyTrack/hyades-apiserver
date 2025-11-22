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

import org.dependencytrack.config.templating.ConfigTemplateRenderer;
import org.dependencytrack.persistence.jdbi.ExtensionConfigDao;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.config.mapping.RuntimeConfigMapper;
import org.jspecify.annotations.NonNull;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.6.0
 */
public final class ConfigRegistryImpl implements MutableConfigRegistry {

    private final String extensionPointName;
    private final String extensionName;
    private final DeploymentConfig deploymentConfig;
    private final RuntimeConfigMapper runtimeConfigMapper;
    private final ConfigTemplateRenderer configTemplateRenderer;
    private final Class<? extends RuntimeConfig> runtimeConfigClass;

    ConfigRegistryImpl(
            final @NonNull String extensionPointName,
            final String extensionName,
            final @NonNull DeploymentConfig deploymentConfig,
            final RuntimeConfigMapper runtimeConfigMapper,
            final Class<? extends RuntimeConfig> runtimeConfigClass,
            final ConfigTemplateRenderer configTemplateRenderer) {
        this.extensionPointName = extensionPointName;
        this.extensionName = extensionName;
        this.deploymentConfig = deploymentConfig;
        this.runtimeConfigMapper = runtimeConfigMapper;
        this.runtimeConfigClass = runtimeConfigClass;
        this.configTemplateRenderer = configTemplateRenderer;
    }

    @Override
    public @NonNull DeploymentConfig getDeploymentConfig() {
        return deploymentConfig;
    }

    @Override
    public RuntimeConfig getRuntimeConfig() {
        final String configYaml = withJdbiHandle(
                handle -> handle.attach(ExtensionConfigDao.class).getConfig(
                        extensionPointName, extensionName));
        if (configYaml == null) {
            return null;
        }

        final RuntimeConfig config = runtimeConfigMapper.deserialize(configYaml, runtimeConfigClass);
        return configTemplateRenderer.renderObject(config);
    }

    @Override
    public void setRuntimeConfig(final @NonNull RuntimeConfig config) {
        requireNonNull(runtimeConfigClass, "runtimeConfigClass is not initialized");
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(config, "runtimeConfig must not be null");

        if (!runtimeConfigClass.isInstance(config)) {
            throw new IllegalArgumentException("""
                    The provided config of type %s is not an instance of the \
                    extension's declared config type %s\
                    """.formatted(config.getClass().getName(), runtimeConfigClass.getName()));
        }

        runtimeConfigMapper.validate(config);

        final String configYaml = runtimeConfigMapper.serialize(config);

        useJdbiTransaction(
                handle -> handle.attach(ExtensionConfigDao.class).saveConfig(
                        extensionPointName, extensionName, configYaml));
    }

}
