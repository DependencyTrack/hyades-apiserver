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
import org.dependencytrack.persistence.jdbi.ExtensionConfigDao;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.runtime.config.RuntimeConfigMapper;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.util.Optional;
import java.util.function.Function;

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
    private final @Nullable Function<String, @Nullable String> secretResolver;

    ConfigRegistryImpl(
            Config config,
            String extensionPointName,
            String extensionName,
            @Nullable RuntimeConfigSpec runtimeConfigSpec,
            @Nullable RuntimeConfigMapper runtimeConfigMapper,
            @Nullable Function<String, @Nullable String> secretResolver) {
        this.extensionPointName = requireNonNull(extensionPointName, "extensionPointName must not be null");
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");
        this.deploymentConfig = new DeploymentConfigImpl(config, extensionPointName, extensionName);
        this.runtimeConfigSpec = runtimeConfigSpec;
        this.runtimeConfigMapper = runtimeConfigMapper;
        this.secretResolver = secretResolver;
    }

    @Override
    public DeploymentConfig getDeploymentConfig() {
        return deploymentConfig;
    }

    @Override
    public Optional<RuntimeConfig> getOptionalRuntimeConfig() {
        if (runtimeConfigSpec == null) {
            return Optional.empty();
        }
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(secretResolver, "secretResolver is not initialized");

        final String configJson = withJdbiHandle(
                handle -> handle.attach(ExtensionConfigDao.class).getConfig(
                        extensionPointName, extensionName));
        if (configJson == null) {
            return Optional.empty();
        }

        final JsonNode configJsonNode = runtimeConfigMapper.validateJson(configJson, runtimeConfigSpec);

        runtimeConfigMapper.resolveSecretRefs(configJsonNode, runtimeConfigSpec, secretResolver);

        final RuntimeConfig runtimeConfig = runtimeConfigMapper.convert(configJsonNode, runtimeConfigSpec.configClass());

        if (runtimeConfigSpec.validator() != null) {
            runtimeConfigSpec.validator().validate(runtimeConfig);
        }

        return Optional.of(runtimeConfig);
    }

    @Override
    public boolean setRuntimeConfig(RuntimeConfig config) {
        requireNonNull(runtimeConfigSpec, "runtimeConfigSpec is not initialized");
        requireNonNull(runtimeConfigMapper, "runtimeConfigMapper is not initialized");
        requireNonNull(config, "config must not be null");

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
