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
package alpine.test.config;

import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * A JUnit 4 {@link TestRule} to set config properties.
 * <p>
 * Properties can be set globally for all {@link org.junit.Test} methods in a class
 * using {@link ConfigPropertyRule#withProperty(String, String)}, or on a per-test basis,
 * using {@link WithConfigProperty} annotations.
 *
 * @since 5.7.0
 */
public class ConfigPropertyRule implements TestRule {

    private final Map<String, String> properties = new HashMap<>();
    private final Map<String, Supplier<String>> propertySuppliers = new HashMap<>();

    @Override
    public Statement apply(final Statement statement, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                MemoryConfigSource.setProperties(properties);

                for (final Map.Entry<String, Supplier<String>> entry : propertySuppliers.entrySet()) {
                    final String name = entry.getKey();
                    final Supplier<String> valueSupplier = entry.getValue();
                    MemoryConfigSource.setProperty(name, valueSupplier.get());
                }

                final var annotation = description.getAnnotation(WithConfigProperty.class);
                if (annotation != null) {
                    Arrays.stream(annotation.value())
                            .map(value -> value.split("=", 2))
                            .filter(valueParts -> valueParts.length == 2)
                            .forEach(valueParts -> MemoryConfigSource.setProperty(valueParts[0], valueParts[1]));
                }

                try {
                    statement.evaluate();
                } finally {
                    MemoryConfigSource.clear();
                }
            }
        };
    }

    public ConfigPropertyRule withProperty(final String key, final String value) {
        properties.put(key, value);
        return this;
    }

    public ConfigPropertyRule withProperty(final String key, final Supplier<String> valueSupplier) {
        propertySuppliers.put(key, valueSupplier);
        return this;
    }

    public ConfigPropertyRule withProperties(final Map<String, String> properties) {
        this.properties.putAll(properties);
        return this;
    }

    public void setProperty(final String key, final String value) {
        MemoryConfigSource.setProperty(key, value);
    }

}