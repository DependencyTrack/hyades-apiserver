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

import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.plugin.api.notification.publishing.TemplateRenderer;
import org.dependencytrack.proto.notification.v1.Notification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
final class TemplateRendererImpl implements TemplateRenderer {

    private final PebbleTemplate template;

    public TemplateRendererImpl(final PebbleTemplate template) {
        this.template = template;
    }

    @Override
    public byte[] render(final Notification notification, final Map<String, Object> additionalContext) {
        requireNonNull(notification, "notification must not be null");

        final var templateCtx = new HashMap<String, Object>();

        // TODO: Cache this?
        //  Very unlikely to change often, but we also don't want a significant
        //  delay between users changing this and it taking effect.
        templateCtx.put("baseUrl",
                withJdbiHandle(handle -> handle.attach(ConfigPropertyDao.class)
                        .getOptionalValue(GENERAL_BASE_URL, String.class))
                        .orElse(null));

        // TODO: Populate more context variables.

        try (final var byteArrayOutputStream = new ByteArrayOutputStream();
             final var outputStreamWriter = new OutputStreamWriter(byteArrayOutputStream)) {
            template.evaluate(outputStreamWriter, templateCtx);
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
