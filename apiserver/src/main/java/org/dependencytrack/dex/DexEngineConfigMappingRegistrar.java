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
package org.dependencytrack.dex;

import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.SmallRyeConfigBuilderCustomizer;
import org.eclipse.microprofile.config.Config;

/**
 * @since 5.7.0
 */
public final class DexEngineConfigMappingRegistrar implements SmallRyeConfigBuilderCustomizer {

    @Override
    public void configBuilder(final SmallRyeConfigBuilder builder) {
        final Config tempConfig = createTempConfig(builder);

        if (tempConfig.getOptionalValue("dt.dex-engine.enabled", boolean.class).orElse(false)) {
            builder.withMapping(DexEngineConfigMapping.class);
        }
    }

    @Override
    public int priority() {
        return Integer.MAX_VALUE;
    }

    private Config createTempConfig(final SmallRyeConfigBuilder builder) {
        final var tempConfigBuilder = new SmallRyeConfigBuilder()
                .withDefaultValues(builder.getDefaultValues())
                .withSources(builder.getSources());

        if (builder.isAddDefaultSources()) {
            tempConfigBuilder.addDefaultSources();
        }

        return tempConfigBuilder.build();
    }

}
