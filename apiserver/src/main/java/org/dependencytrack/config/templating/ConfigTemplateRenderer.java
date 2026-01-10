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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.cache.template.CaffeineTemplateCache;
import io.pebbletemplates.pebble.loader.StringLoader;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Renderer of configuration templates.
 * <p>
 * Templates are meant to be used for <em>runtime</em> configuration
 * only, i.e. configuration stored in the database.
 * <em>Deployment</em> configuration, sourced from properties files,
 * environment variables, and similar, should <strong>not</strong> use templating.
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

    private static final Pattern TEMPLATE_PATTERN = Pattern.compile(".*\\{\\{.+}}.*");

    private final PebbleEngine pebbleEngine;

    public ConfigTemplateRenderer(Function<String, @Nullable String> secretResolver) {
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
                .extension(new ConfigTemplatePebbleExtension(secretResolver))
                // Apply customizations to built-in extension(s).
                .registerExtensionCustomizer(ConfigTemplatePebbleExtensionCustomizer::new)
                .build();
    }

    public @Nullable String render(@Nullable String value) {
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

    public void renderJson(@Nullable JsonNode jsonNode) {
        if (jsonNode instanceof final ObjectNode objectNode) {
            renderJsonObjectNode(objectNode);
        } else if (jsonNode instanceof final ArrayNode arrayNode) {
            renderJsonArrayNode(arrayNode);
        }
    }

    private void renderJsonObjectNode(ObjectNode objectNode) {
        for (final Map.Entry<String, JsonNode> property : objectNode.properties()) {
            final String propertyName = property.getKey();
            final JsonNode propertyValue = property.getValue();

            if (propertyValue.isTextual()) {
                final String originalValue = propertyValue.asText();
                final String renderedValue = render(originalValue);

                if (renderedValue != null && !renderedValue.equals(originalValue)) {
                    objectNode.set(propertyName, TextNode.valueOf(renderedValue));
                }
            } else {
                renderJson(propertyValue);
            }
        }
    }

    private void renderJsonArrayNode(ArrayNode arrayNode) {
        for (int i = 0; i < arrayNode.size(); i++) {
            final JsonNode itemNode = arrayNode.get(i);

            if (itemNode.isTextual()) {
                final String originalValue = itemNode.asText();
                final String renderedValue = render(originalValue);

                if (renderedValue != null && !renderedValue.equals(originalValue)) {
                    arrayNode.set(i, TextNode.valueOf(renderedValue));
                }
            } else {
                renderJson(itemNode);
            }
        }
    }

}