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

import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * A read-only view on the configuration associated with a notification rule.
 *
 * @since 5.7.0
 */
public interface NotificationRuleConfig {

    <T> Optional<T> getOptionalValue(RuntimeConfigDefinition<T> configDef);

    default <T> T getValue(RuntimeConfigDefinition<T> configDef) {
        return getOptionalValue(configDef).orElseThrow(NoSuchElementException::new);
    }

}
