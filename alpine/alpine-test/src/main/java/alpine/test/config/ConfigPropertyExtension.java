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
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * A JUnit Jupiter extension to set config properties.
 * <p>
 * Properties can be set globally for all test methods in a class
 * using {@link ConfigPropertyExtension#withProperty(String, String)}, or on a per-test basis,
 * using {@link WithConfigProperty} annotations.
 *
 * @since 5.7.0
 */
public class ConfigPropertyExtension implements BeforeEachCallback, AfterEachCallback, ParameterResolver {

    private final Map<String, String> properties = new HashMap<>();
    private final Map<String, Supplier<String>> propertySuppliers = new HashMap<>();

    @Override
    public void beforeEach(ExtensionContext context) {
        MemoryConfigSource.setProperties(properties);

        for (final Map.Entry<String, Supplier<String>> entry : propertySuppliers.entrySet()) {
            final String name = entry.getKey();
            final Supplier<String> valueSupplier = entry.getValue();
            MemoryConfigSource.setProperty(name, valueSupplier.get());
        }

        context.getTestMethod().ifPresent(method -> {
            final var annotation = method.getAnnotation(WithConfigProperty.class);
            if (annotation != null) {
                Arrays.stream(annotation.value())
                        .map(value -> value.split("=", 2))
                        .filter(valueParts -> valueParts.length == 2)
                        .forEach(valueParts -> MemoryConfigSource.setProperty(valueParts[0], valueParts[1]));
            }
        });
    }

    @Override
    public void afterEach(ExtensionContext context) {
        MemoryConfigSource.clear();
    }

    public ConfigPropertyExtension withProperty(String key, String value) {
        properties.put(key, value);
        return this;
    }

    public ConfigPropertyExtension withProperty(String key, Supplier<String> valueSupplier) {
        propertySuppliers.put(key, valueSupplier);
        return this;
    }

    public ConfigPropertyExtension withProperties(Map<String, String> properties) {
        this.properties.putAll(properties);
        return this;
    }

    public void setProperty(String key, String value) {
        MemoryConfigSource.setProperty(key, value);
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return parameterContext.getParameter().getType().equals(ConfigPropertyExtension.class);
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return this;
    }

}
