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

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.config.templating.ConfigTemplateRenderer;
import org.dependencytrack.persistence.jdbi.ExtensionConfigDao;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.runtime.config.RuntimeConfigMapper;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.6.0
 */
public final class ConfigRegistryImpl implements MutableConfigRegistry {

    private final String extensionPointName;
    private final String extensionName;
    private final DeploymentConfig deploymentConfig;
    private final @Nullable RuntimeConfigSpec runtimeConfigSpec;
    private final @Nullable RuntimeConfigMapper runtimeConfigMapper;
    private final @Nullable ConfigTemplateRenderer configTemplateRenderer;

    ConfigRegistryImpl(
            Config config,
            String extensionPointName,
            String extensionName,
            @Nullable RuntimeConfigSpec runtimeConfigSpec,
            @Nullable RuntimeConfigMapper runtimeConfigMapper,
            @Nullable ConfigTemplateRenderer configTemplateRenderer) {
        this.extensionPointName = requireNonNull(extensionPointName, "extensionPointName must not be null");
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");
        this.deploymentConfig = new DeploymentConfigImpl(config, extensionPointName, extensionName);
        this.runtimeConfigSpec = runtimeConfigSpec;
        this.runtimeConfigMapper = runtimeConfigMapper;
        this.configTemplateRenderer = configTemplateRenderer;
    }

    @Override
    public DeploymentConfig getDeploymentConfig() {
        return deploymentConfig;
    }

    @Override
    public @Nullable RuntimeConfig getRuntimeConfig() {
        if (runtimeConfigSpec == null) {
            return null;
        }
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(configTemplateRenderer, "configTemplateRenderer is not initialized");

        final String configJson = withJdbiHandle(
                handle -> handle.attach(ExtensionConfigDao.class).getConfig(
                        extensionPointName, extensionName));
        if (configJson == null) {
            return null;
        }

        final JsonNode configJsonNode = runtimeConfigMapper.validateJson(configJson, runtimeConfigSpec);

        configTemplateRenderer.renderJson(configJsonNode);

        return runtimeConfigMapper.convert(configJsonNode, runtimeConfigSpec.configClass());
    }

    @Override
    public boolean setRuntimeConfig(RuntimeConfig config) {
        requireNonNull(runtimeConfigSpec, "runtimeConfigSpec is not initialized");
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(config, "runtimeConfig must not be null");

        if (!runtimeConfigSpec.configClass().isInstance(config)) {
            throw new IllegalArgumentException("""
                    The provided config of type %s is not an instance of the \
                    extension's declared config type %s\
                    """.formatted(config.getClass().getName(), runtimeConfigSpec.configClass().getName()));
        }

        runtimeConfigMapper.validate(config, runtimeConfigSpec);

        final String configJson = runtimeConfigMapper.serialize(config);

        return inJdbiTransaction(
                handle -> handle.attach(ExtensionConfigDao.class).saveConfig(
                        extensionPointName, extensionName, configJson));
    }

}
