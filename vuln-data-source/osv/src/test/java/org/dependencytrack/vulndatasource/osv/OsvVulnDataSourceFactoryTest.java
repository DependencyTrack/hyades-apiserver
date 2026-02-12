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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.vulndatasource.osv.WatermarkManager.getWatermarkManager;

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
    void createWhenIncrementalMirroringDisabledShouldCreateDataSourceWithNullWatermarkManager() throws Exception {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(false);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);
        factory.init(new ExtensionContext(configRegistry));

        try (VulnDataSource dataSource = factory.create()) {
            assertThat(dataSource).isNotNull();
            assertThat(dataSource).isInstanceOf(OsvVulnDataSource.class);
            assertThat(getWatermarkManager(dataSource)).isNull();
        }
    }

    @Test
    void createWhenIncrementalMirroringEnabledShouldCreateDataSourceWithWatermarkManager() throws Exception {
        final var config = (OsvVulnDataSourceConfigV1) factory.runtimeConfigSpec().defaultConfig();
        config.setEnabled(true);
        config.setIncrementalMirroringEnabled(true);

        final var configRegistry = new MockConfigRegistry(factory.runtimeConfigSpec(), config);
        factory.init(new ExtensionContext(configRegistry));

        try (VulnDataSource dataSource = factory.create()) {
            assertThat(dataSource).isNotNull();
            assertThat(dataSource).isInstanceOf(OsvVulnDataSource.class);
            assertThat(getWatermarkManager(dataSource)).isNotNull();
        }
    }


}