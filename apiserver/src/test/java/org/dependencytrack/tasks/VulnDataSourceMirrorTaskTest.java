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
package org.dependencytrack.tasks;

import org.dependencytrack.event.VulnDataSourceMirrorEvent;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSourceFactory;
import org.junit.Test;

import java.util.Comparator;
import java.util.TreeSet;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class VulnDataSourceMirrorTaskTest {

    @Test
    public void shouldMirrorAllDataSources() {
        final var pluginManagerMock = mock(PluginManager.class);

        final var dataSourceFactoryMockA = mock(VulnDataSourceFactory.class);
        doReturn("a").when(dataSourceFactoryMockA).extensionName();

        final var dataSourceFactoryMockB = mock(VulnDataSourceFactory.class);
        doReturn("b").when(dataSourceFactoryMockB).extensionName();

        final var dataSourceFactories = new TreeSet<>(
                Comparator.comparing(VulnDataSourceFactory::extensionName));
        dataSourceFactories.add(dataSourceFactoryMockA);
        dataSourceFactories.add(dataSourceFactoryMockB);

        doReturn(dataSourceFactories).when(pluginManagerMock).getFactories(eq(VulnDataSource.class));

        final var task = new VulnDataSourceMirrorTask(pluginManagerMock, 10);
        task.inform(new VulnDataSourceMirrorEvent());

        verify(dataSourceFactoryMockA).create();
        verify(dataSourceFactoryMockB).create();
    }

}