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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @since 5.6.0
 */
public final class ConfigUtil {

    private ConfigUtil() {
    }

    /**
     * Copy of {@link Config#getPassThroughProperties(String)} that omits the {@code "alpine."} prefix requirement.
     *
     * @param config The {@link Config} to use
     * @param prefix Prefix of the properties to fetch
     * @return A {@link Map} containing the matched properties
     * @see Config#getPassThroughProperties(String)
     */
    public static Map<String, String> getPassThroughProperties(final Config config, final String prefix) {
        final Properties properties;
        try {
            final Field propertiesField = Config.class.getDeclaredField("properties");
            propertiesField.setAccessible(true);
            properties = (Properties) propertiesField.get(config);
        } catch (final NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalStateException("Unable to access Config properties", e);
        }

        final var passThroughProperties = new HashMap<String, String>();
        try {
            for (final Map.Entry<String, String> envVar : System.getenv().entrySet()) {
                if (envVar.getKey().startsWith("%s_".formatted(prefix.toUpperCase().replace(".", "_")))) {
                    final String key = envVar.getKey().toLowerCase().replace("_", ".");
                    passThroughProperties.put(key, envVar.getValue());
                }
            }
        } catch (SecurityException e) {
            throw new IllegalStateException("""
                    Unable to retrieve pass-through properties for prefix "%s" \
                    from environment variables""".formatted(prefix), e);
        }

        for (final Map.Entry<Object, Object> property : properties.entrySet()) {
            if (property.getKey() instanceof String key
                && key.startsWith("%s.".formatted(prefix))
                && property.getValue() instanceof final String value) {
                if (!passThroughProperties.containsKey(key)) { // Environment variables take precedence
                    passThroughProperties.put(key, value);
                }
            }
        }

        return passThroughProperties;
    }

}
