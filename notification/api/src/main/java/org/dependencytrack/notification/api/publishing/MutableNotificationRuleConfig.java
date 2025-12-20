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
package org.dependencytrack.notification.api.publishing;

import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public class MutableNotificationRuleConfig implements NotificationRuleConfig {

    private final Map<String, String> valueByName;

    MutableNotificationRuleConfig(Map<String, String> valueByName) {
        this.valueByName = requireNonNull(valueByName, "valueByName must not be null");
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public static MutableNotificationRuleConfig ofDefaults(NotificationPublisherFactory publisherFactory) {
        final var valueByName = new HashMap<String, String>(publisherFactory.ruleConfigs().size());

        for (final RuntimeConfigDefinition configDef : publisherFactory.ruleConfigs()) {
            final String defaultValue = configDef.type().toString(configDef.defaultValue());
            valueByName.put(configDef.name(), defaultValue);
        }

        return new MutableNotificationRuleConfig(valueByName);
    }

    @Override
    public <T> Optional<T> getOptionalValue(RuntimeConfigDefinition<T> configDef) {
        final String value = valueByName.get(configDef.name());

        if (value == null && configDef.isRequired()) {
            throw new IllegalStateException("""
                    Config %s is defined as required, but no value has been found\
                    """.formatted(configDef.name()));
        }

        return Optional.ofNullable(configDef.type().fromString(value));
    }

    public <T> void setValue(RuntimeConfigDefinition<T> configDef, final T value) {
        if (configDef.isRequired() && value == null) {
            throw new IllegalArgumentException(
                    "Config %s is defined as required, but value is null".formatted(configDef.name()));
        }

        valueByName.put(configDef.name(), configDef.type().toString(value));
    }

}
