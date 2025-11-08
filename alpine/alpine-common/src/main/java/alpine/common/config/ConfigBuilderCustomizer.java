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
package alpine.common.config;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.Priorities;
import io.smallrye.config.RelocateConfigSourceInterceptor;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.SmallRyeConfigBuilderCustomizer;

import java.util.Map;
import java.util.OptionalInt;

import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_LOCATIONS;
import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_LOG_VALUES;
import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_MAPPING_VALIDATE_UNKNOWN;
import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_PROFILE;
import static io.smallrye.config.SmallRyeConfig.SMALLRYE_CONFIG_PROFILE_PARENT;

/**
 * @since 5.7.0
 */
public final class ConfigBuilderCustomizer implements SmallRyeConfigBuilderCustomizer {

    @Override
    public void configBuilder(final SmallRyeConfigBuilder builder) {
        builder
                // Relocate SmallRye properties to the Alpine prefix for better framework "immersion".
                // https://smallrye.io/smallrye-config/Main/extensions/relocate/
                .withInterceptorFactories(new ConfigSourceInterceptorFactory() {

                    @Override
                    public ConfigSourceInterceptor getInterceptor(final ConfigSourceInterceptorContext context) {
                        // Properties to be relocated are documented here:
                        // https://smallrye.io/smallrye-config/Main/config/configuration/
                        return new RelocateConfigSourceInterceptor(Map.ofEntries(
                                Map.entry(SMALLRYE_CONFIG_PROFILE, "alpine.config.profile"),
                                Map.entry(SMALLRYE_CONFIG_PROFILE_PARENT, "alpine.config.profile.parent"),
                                Map.entry(SMALLRYE_CONFIG_LOCATIONS, "alpine.config.locations"),
                                Map.entry(SMALLRYE_CONFIG_LOG_VALUES, "alpine.config.log.values"),
                                Map.entry(SMALLRYE_CONFIG_MAPPING_VALIDATE_UNKNOWN, "alpine.config.mapping.validate-unknown")));
                    }

                    @Override
                    public OptionalInt getPriority() {
                        // Priority must be higher than that of ProfileConfigSourceInterceptor
                        // in order for profile property relocations to work.
                        return OptionalInt.of(Priorities.LIBRARY + 210);
                    }

                })
                // Always redirect Alpine build info properties to the respective
                // alpine.version and application.version property files.
                .withInterceptorFactories(
                        new PropertyFileConfigSourceInterceptorFactory(
                                Thread.currentThread().getContextClassLoader().getResource("alpine.version"),
                                Map.ofEntries(
                                        Map.entry("alpine.build-info.framework.name", "name"),
                                        Map.entry("alpine.build-info.framework.version", "version"),
                                        Map.entry("alpine.build-info.framework.uuid", "uuid"),
                                        Map.entry("alpine.build-info.framework.timestamp", "timestamp"))),
                        new PropertyFileConfigSourceInterceptorFactory(
                                Thread.currentThread().getContextClassLoader().getResource("application.version"),
                                Map.ofEntries(
                                        Map.entry("alpine.build-info.application.name", "name"),
                                        Map.entry("alpine.build-info.application.version", "version"),
                                        Map.entry("alpine.build-info.application.uuid", "uuid"),
                                        Map.entry("alpine.build-info.application.timestamp", "timestamp"))))
                .withDefaultValue("alpine.config.mapping.validate-unknown", "false")
                .withDefaultValue("alpine.config.profile", "prod")
                // Add declarative mapping for Alpine configuration.
                .withMapping(BuildInfoConfig.class);
    }

}
