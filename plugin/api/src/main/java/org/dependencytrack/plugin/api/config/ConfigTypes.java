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
package org.dependencytrack.plugin.api.config;

import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * @since 5.7.0
 */
public final class ConfigTypes {

    public static final ConfigType<Boolean> BOOLEAN = new ConfigType.Boolean();
    public static final ConfigType<Duration> DURATION = new ConfigType.Duration();
    public static final ConfigType<Instant> INSTANT = new ConfigType.Instant();
    public static final ConfigType<Integer> INTEGER = new ConfigType.Integer();
    public static final ConfigType<Path> PATH = new ConfigType.Path();
    public static final ConfigType<String> STRING = new ConfigType.String();
    public static ConfigType<List<String>> stringList(Set<String> allowedValues) {
        return new ConfigType.StringList(allowedValues);
    }
    public static final ConfigType<URL> URL = new ConfigType.URL();

    private ConfigTypes() {
    }

}
