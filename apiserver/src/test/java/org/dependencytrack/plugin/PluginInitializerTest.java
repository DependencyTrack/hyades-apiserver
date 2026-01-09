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

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourcePlugin;
import org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourcePlugin;
import org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourcePlugin;
import org.dependencytrack.filestorage.local.LocalFileStoragePlugin;
import org.dependencytrack.filestorage.memory.MemoryFileStoragePlugin;
import org.dependencytrack.filestorage.s3.S3FileStoragePlugin;
import org.dependencytrack.notification.publishing.DefaultNotificationPublisherPlugin;
import org.dependencytrack.plugin.api.ExtensionPointSpec;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PluginInitializerTest extends PersistenceCapableTest {

    private final List<Runnable> cleanupTasks = new ArrayList<>();

    @AfterEach
    void afterEach() {
        cleanupTasks.forEach(Runnable::run);
    }

    @Test
    void shouldLoadAndUnloadPlugins() {
        // Test against "production" config for more realistic test coverage.
        final Config config = ConfigProvider.getConfig();

        final var servletContextMock = mock(ServletContext.class);
        final var attributeNameCaptor = ArgumentCaptor.forClass(String.class);
        final var attributeValueCaptor = ArgumentCaptor.forClass(Object.class);

        final var initializer = new PluginInitializer(config);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(servletContextMock).setAttribute(
                attributeNameCaptor.capture(),
                attributeValueCaptor.capture());

        assertThat(attributeNameCaptor.getValue()).isEqualTo(PluginManager.class.getName());

        final var pluginManager = (PluginManager) attributeValueCaptor.getValue();
        assertThat(pluginManager).isNotNull();
        assertThat(pluginManager.isClosed()).isFalse();

        // Make sure resources are released even when the following assertions fail.
        cleanupTasks.add(pluginManager::close);

        assertThat(pluginManager.getExtensionPoints())
                .extracting(ExtensionPointSpec::name)
                .containsExactlyInAnyOrder(
                        "file.storage",
                        "notification.publisher",
                        "vuln.datasource");
        assertThat(pluginManager.getLoadedPlugins()).satisfiesExactlyInAnyOrder(
                plugin -> assertThat(plugin).isInstanceOf(DefaultNotificationPublisherPlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(GitHubVulnDataSourcePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(LocalFileStoragePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(MemoryFileStoragePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(NvdVulnDataSourcePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(OsvVulnDataSourcePlugin.class),
                plugin -> assertThat(plugin).isInstanceOf(S3FileStoragePlugin.class));

        initializer.contextDestroyed(new ServletContextEvent(servletContextMock));

        assertThat(pluginManager.isClosed()).isTrue();

        verify(servletContextMock).removeAttribute(eq(PluginManager.class.getName()));
    }

}