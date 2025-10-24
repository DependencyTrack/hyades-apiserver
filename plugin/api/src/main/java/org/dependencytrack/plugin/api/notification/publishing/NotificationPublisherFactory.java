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
package org.dependencytrack.plugin.api.notification.publishing;

import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.SequencedCollection;

/**
 * @since 5.7.0
 */
public interface NotificationPublisherFactory extends ExtensionFactory<NotificationPublisher> {

    /**
     * @return Definitions of configs that may be scoped to notification rules.
     * Publisher instances will be able to access their values at runtime via
     * {@link PublishContext#ruleConfig()}.
     */
    default SequencedCollection<RuntimeConfigDefinition<?>> ruleConfigs() {
        return Collections.emptyList();
    }

    /**
     * @return The default template of the publisher. May be {@code null}.
     */
    default String defaultTemplate() {
        try (final InputStream inputStream = getClass().getResourceAsStream("default-template.peb")) {
            if (inputStream == null) {
                throw new IllegalStateException("Default template could not be found");
            }

            return new String(inputStream.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
