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
package org.dependencytrack.config.templating;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.cache.template.CaffeineTemplateCache;
import io.pebbletemplates.pebble.loader.StringLoader;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.secret.SecretManagerInitializer;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Renderer of configuration templates.
 * <p>
 * Configuration templates are authored by administrative users
 * and have access to confidential information such as secrets.
 * <p>
 * The underlying Pebble template engine has been severely restricted
 * to a small subset of its capabilities. Control flow, embeds, includes,
 * and similar meta constructs are not available. Access to fields and
 * methods of Java objects is disallowed.
 * <p>
 * Rendered templates are not intended to ever be disclosed to
 * users or REST API clients.
 *
 * @since 5.7.0
 */
public final class ConfigTemplateRenderer {

    private static final ConfigTemplateRenderer INSTANCE = new ConfigTemplateRenderer();
    private static final Pattern TEMPLATE_PATTERN = Pattern.compile(".*\\{\\{.*}}.*");

    private final PebbleEngine pebbleEngine;
    private final ObjectGraphStringTransformer objectGraphStringTransformer;

    ConfigTemplateRenderer(final Function<String, @Nullable String> secretResolver) {
        this.pebbleEngine = new PebbleEngine.Builder()
                // Prevent loading from any external location.
                .loader(new StringLoader())
                // Cache compiled templates.
                .templateCache(new CaffeineTemplateCache())
                // Prevent access to all fields and methods of objects.
                .methodAccessValidator((object, method) -> false)
                // Throw exception when encountering unknown variables,
                // rather than just rendering them as empty string.
                .strictVariables(true)
                // Limit the size of the rendered content. This value is not set
                // in stone, we can adjust it if there are legitimate cases where
                // more than 1024 characters are needed.
                .maxRenderedSize(1024)
                // Register extension with features for config variable rendering,
                // e.g. secret support.
                .extension(new ConfigTemplateExtension(secretResolver))
                // Apply customizations to built-in extension(s).
                .registerExtensionCustomizer(ConfigTemplateExtensionCustomizer::new)
                .build();
        this.objectGraphStringTransformer =
                new ObjectGraphStringTransformer(
                        /* objectTraversalLimit */ 10,
                        /* collectionSizeLimit */ 50);
    }

    public ConfigTemplateRenderer() {
        this(secretName -> SecretManagerInitializer.INSTANCE.getSecretValue(secretName));
    }

    public static ConfigTemplateRenderer getInstance() {
        return INSTANCE;
    }

    public @Nullable String render(final @Nullable String value) {
        if (value == null) {
            return null;
        }
        if (!TEMPLATE_PATTERN.matcher(value).matches()) {
            // No point in bothering the template engine with this.
            return value;
        }

        final PebbleTemplate template = pebbleEngine.getLiteralTemplate(value);

        try (final var writer = new StringWriter()) {
            template.evaluate(writer);
            return writer.toString();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> @Nullable T renderObject(final @Nullable T value) {
        if (value == null) {
            return null;
        }

        try {
            objectGraphStringTransformer.transform(value, this::render);
        } catch (Throwable e) {
            throw new IllegalStateException(e);
        }

        return value;
    }

}