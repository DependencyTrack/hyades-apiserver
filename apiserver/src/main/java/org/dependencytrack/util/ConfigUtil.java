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
package org.dependencytrack.util;

import alpine.Config;
import io.smallrye.config.SmallRyeConfig;
import org.eclipse.microprofile.config.ConfigProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * @since 5.6.0
 */
public final class ConfigUtil {

    private ConfigUtil() {
    }

    /**
     * Copy of {@link Config#getPassThroughProperties(String)} that omits the {@code "alpine."} prefix requirement.
     *
     * @param prefix Prefix of the properties to fetch
     * @return A {@link Map} containing the matched properties
     * @see Config#getPassThroughProperties(String)
     */
    public static Map<String, String> getPassThroughProperties(final String prefix) {
        final var passThroughProperties = new HashMap<String, String>();

        for (final String propertyName : ConfigProvider.getConfig().unwrap(SmallRyeConfig.class).getLatestPropertyNames()) {
            if (propertyName.startsWith("%s.".formatted(prefix))) {
                ConfigProvider.getConfig()
                        .getOptionalValue(propertyName, String.class)
                        .ifPresent(value -> passThroughProperties.put(propertyName, value));
            }

        }

        return passThroughProperties;
    }

}
