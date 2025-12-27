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

import io.pebbletemplates.pebble.attributes.AttributeResolver;
import io.pebbletemplates.pebble.extension.Extension;
import io.pebbletemplates.pebble.extension.ExtensionCustomizer;
import io.pebbletemplates.pebble.extension.Filter;
import io.pebbletemplates.pebble.extension.NodeVisitorFactory;
import io.pebbletemplates.pebble.extension.Test;
import io.pebbletemplates.pebble.extension.core.Base64DecoderFilter;
import io.pebbletemplates.pebble.extension.core.Base64EncoderFilter;
import io.pebbletemplates.pebble.operator.BinaryOperator;
import io.pebbletemplates.pebble.operator.UnaryOperator;
import io.pebbletemplates.pebble.tokenParser.TokenParser;
import org.jspecify.annotations.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNullElse;

/**
 * @since 5.7.0
 */
final class ConfigTemplatePebbleExtensionCustomizer extends ExtensionCustomizer {

    private static final Set<String> ALLOWED_CORE_FILTERS = Set.of(
            Base64DecoderFilter.FILTER_NAME,
            Base64EncoderFilter.FILTER_NAME,
            "default",
            "lower",
            "trim",
            "upper",
            "urlencode");

    ConfigTemplatePebbleExtensionCustomizer(Extension delegate) {
        super(delegate);
    }

    @Override
    public Map<String, Filter> getFilters() {
        return requireNonNullElse(super.getFilters(), Collections.<String, Filter>emptyMap()).entrySet().stream()
                .filter(entry -> ALLOWED_CORE_FILTERS.contains(entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public @Nullable Map<String, Test> getTests() {
        return null;
    }

    @Override
    public @Nullable Map<String, io.pebbletemplates.pebble.extension.Function> getFunctions() {
        return null;
    }

    @Override
    public @Nullable List<TokenParser> getTokenParsers() {
        return null;
    }

    @Override
    public @Nullable List<BinaryOperator> getBinaryOperators() {
        return super.getBinaryOperators();
    }

    @Override
    public @Nullable List<UnaryOperator> getUnaryOperators() {
        return super.getUnaryOperators();
    }

    @Override
    public @Nullable Map<String, Object> getGlobalVariables() {
        return null;
    }

    @Override
    public @Nullable List<NodeVisitorFactory> getNodeVisitors() {
        return null;
    }

    @Override
    public @Nullable List<AttributeResolver> getAttributeResolver() {
        return null;
    }

}
