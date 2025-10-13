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
package org.dependencytrack.plugin;

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;
import org.dependencytrack.plugin.api.config.RuntimeConfigDefinition;

public class DummyTestExtensionFactory implements ExtensionFactory<TestExtensionPoint> {

    private static final ConfigDefinition<String> CONFIG_FOO =
            new RuntimeConfigDefinition<>("foo", "description", ConfigTypes.STRING, null, false, false);
    private static final ConfigDefinition<String> CONFIG_BAR =
            new DeploymentConfigDefinition<>("bar", ConfigTypes.STRING, false);

    private ConfigRegistry configRegistry;

    @Override
    public String extensionName() {
        return DummyTestExtension.NAME;
    }

    @Override
    public Class<? extends TestExtensionPoint> extensionClass() {
        return DummyTestExtension.class;
    }

    @Override
    public int priority() {
        return PRIORITY_LOWEST;
    }

    @Override
    public void init(final ExtensionContext ctx) {
        this.configRegistry = ctx.configRegistry();
    }

    @Override
    public DummyTestExtension create() {
        return new DummyTestExtension(
                configRegistry.getOptionalValue(CONFIG_FOO).orElse(null),
                configRegistry.getOptionalValue(CONFIG_BAR).orElse(null)
        );
    }

}
