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
package org.dependencytrack.vulndatasource.osv;

import java.lang.reflect.Field;

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class OsvVulnDataSourceFactoryTest extends AbstractExtensionFactoryTest<@NonNull VulnDataSource, @NonNull OsvVulnDataSourceFactory> {

    protected OsvVulnDataSourceFactoryTest() {
        super(OsvVulnDataSourceFactory.class);
    }

    @Test
    void extensionNameShouldBeOsv() {
        assertThat(factory.extensionName()).isEqualTo("osv");
    }

    @Test
    void extensionClassShouldBeOsvVulnDataSource() {
        assertThat(factory.extensionClass()).isEqualTo(OsvVulnDataSource.class);
    }

    @Test
    void priorityShouldBeZero() {
        assertThat(factory.priority()).isEqualTo(100);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isDataSourceEnabledShouldReturnTrueWhenEnabledAndFalseOtherwise(final boolean isEnabled) {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(isEnabled);

        factory.init(new ExtensionContext(new MockConfigRegistry(factory.runtimeConfigSpec(), config)));
        assertThat(factory.isDataSourceEnabled()).isEqualTo(isEnabled);
    }

    @Test
    void createShouldReturnNullWhenDisabled() {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(factory::create);
    }

    @Test
    void createShouldReturnDataSource() {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        dataSource.close();
    }

    @Test
    void createShouldCreateWatermarkManagerWhenIncrementalMirroringEnabled() throws Exception {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(true); // Explicitly enable incremental mirroring

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        // Step 1: Create data source
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(dataSource).isInstanceOf(OsvVulnDataSource.class);

        // Step 2: Verify watermark manager is NOT null when incremental mirroring is enabled
        final OsvVulnDataSource osvDataSource = (OsvVulnDataSource) dataSource;
        final Field watermarkManagerField = OsvVulnDataSource.class.getDeclaredField("watermarkManager");
        watermarkManagerField.setAccessible(true);
        final Object watermarkManager = watermarkManagerField.get(osvDataSource);
        assertThat(watermarkManager)
                .as("Watermark manager should be created when incremental mirroring is enabled")
                .isNotNull();

        // Step 3: Verify data source can be closed without errors
        assertThatNoException()
                .isThrownBy(dataSource::close);
    }

    @Test
    void createShouldNotCreateWatermarkManagerWhenIncrementalMirroringDisabled() throws Exception {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(false); // Disable incremental mirroring

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        // Step 1: Create data source
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(dataSource).isInstanceOf(OsvVulnDataSource.class);

        // Step 2: Verify watermark manager IS null when incremental mirroring is disabled
        final OsvVulnDataSource osvDataSource = (OsvVulnDataSource) dataSource;
        final Field watermarkManagerField = OsvVulnDataSource.class.getDeclaredField("watermarkManager");
        watermarkManagerField.setAccessible(true);
        final Object watermarkManager = watermarkManagerField.get(osvDataSource);
        assertThat(watermarkManager)
                .as("Watermark manager should be null when incremental mirroring is disabled")
                .isNull();

        // Step 3: Verify data source can be closed without errors (no watermark manager to commit)
        assertThatNoException()
                .isThrownBy(dataSource::close);
    }

    @Test
    void createShouldDefaultToIncrementalMirroringEnabled() throws Exception {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        // Don't set incrementalMirroringEnabled - should default to true

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);

        factory.init(new ExtensionContext(configRegistry));

        // Step 1: Create data source with default config (incremental mirroring not explicitly set)
        final VulnDataSource dataSource = factory.create();
        assertThat(dataSource).isNotNull();
        assertThat(dataSource).isInstanceOf(OsvVulnDataSource.class);

        // Step 2: Verify watermark manager is NOT null by default (incremental mirroring enabled by default)
        final OsvVulnDataSource osvDataSource = (OsvVulnDataSource) dataSource;
        final Field watermarkManagerField = OsvVulnDataSource.class.getDeclaredField("watermarkManager");
        watermarkManagerField.setAccessible(true);
        final Object watermarkManager = watermarkManagerField.get(osvDataSource);
        assertThat(watermarkManager)
                .as("Watermark manager should be created by default (incremental mirroring enabled by default)")
                .isNotNull();

        // Step 3: Verify default config value is true
        assertThat(config.isIncrementalMirroringEnabled())
                .as("Default value of incrementalMirroringEnabled should be true")
                .isTrue();

        // Step 4: Verify data source can be closed without errors
        assertThatNoException()
                .isThrownBy(dataSource::close);
    }

}