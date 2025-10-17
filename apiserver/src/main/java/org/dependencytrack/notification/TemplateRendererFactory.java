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
package org.dependencytrack.notification;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.extension.core.DisallowExtensionCustomizerBuilder;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.plugin.api.notification.publishing.TemplateRenderer;
import org.jspecify.annotations.NonNull;

import java.time.Duration;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class TemplateRendererFactory {

    private final PebbleEngine pebbleEngine;
    private final Cache<@NonNull Integer, PebbleTemplate> templateCache;

    TemplateRendererFactory() {
        this.pebbleEngine = new PebbleEngine.Builder()
                .registerExtensionCustomizer(new DisallowExtensionCustomizerBuilder()
                        .disallowedTokenParserTags(List.of("include"))
                        .build())
                .defaultEscapingStrategy("json")
                .build();
        this.templateCache = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(5))
                .build();
    }

    public TemplateRenderer create(final String templateLiteral) {
        requireNonNull(templateLiteral, "templateLiteral must not be null");

        // Templates are thread safe and relatively expensive to create.
        // It makes sense to cache them for a while to account for times
        // during which many notifications are being sent.
        final PebbleTemplate template = templateCache.get(
                templateLiteral.hashCode(),
                ignored -> pebbleEngine.getLiteralTemplate(templateLiteral));

        return new TemplateRendererImpl(template);
    }

}
