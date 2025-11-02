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
package org.dependencytrack.plugin.testing;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.config.mapping.RuntimeConfigMapper;
import org.jspecify.annotations.Nullable;

import java.util.Collections;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * An in-memory {@link MutableConfigRegistry} suitable for testing purposes.
 *
 * @since 5.7.0
 */
public final class MockConfigRegistry implements MutableConfigRegistry {

    private final DeploymentConfig deploymentConfig;
    private final @Nullable RuntimeConfigMapper runtimeConfigMapper;
    private final @Nullable Class<? extends RuntimeConfig> runtimeConfigClass;
    private volatile @Nullable RuntimeConfig runtimeConfig;

    public MockConfigRegistry(
            final @Nullable Map<String, String> deploymentConfigs,
            final @Nullable RuntimeConfigMapper runtimeConfigMapper,
            final @Nullable Class<? extends RuntimeConfig> runtimeConfigClass,
            final @Nullable RuntimeConfig runtimeConfig) {
        this.deploymentConfig = new DelegatingDeploymentConfig(
                new SmallRyeConfigBuilder()
                        .withDefaultValues(deploymentConfigs)
                        .build());
        this.runtimeConfigMapper = runtimeConfigMapper;
        this.runtimeConfigClass = runtimeConfigClass;
        if (runtimeConfig != null) {
            setRuntimeConfig(runtimeConfig);
        }
    }

    public MockConfigRegistry(final Map<String, String> deploymentConfigs) {
        this(deploymentConfigs, null, null, null);
    }

    public MockConfigRegistry(final RuntimeConfig runtimeConfig) {
        this(
                Collections.emptyMap(),
                runtimeConfig != null ? RuntimeConfigMapper.getInstance() : null,
                runtimeConfig != null ? runtimeConfig.getClass() : null,
                runtimeConfig);
    }

    public MockConfigRegistry() {
        this(Collections.emptyMap(), null, null, null);
    }

    @Override
    public DeploymentConfig getDeploymentConfig() {
        return deploymentConfig;
    }

    @Override
    public @Nullable RuntimeConfig getRuntimeConfig() {
        return runtimeConfig;
    }

    @Override
    public void setRuntimeConfig(final RuntimeConfig config) {
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

        this.runtimeConfig = config;
    }

}
