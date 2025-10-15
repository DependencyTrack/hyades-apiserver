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
package org.dependencytrack.datasource.vuln.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_WATERMARKS;

class WatermarkManagerTest {

    private static ConfigRegistry configRegistry;
    private static ObjectMapper mapper;

    @BeforeAll
    static void beforeClass() {
        configRegistry = new MockConfigRegistry();
        mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @Test
    void createShouldInitializeWatermarkWhenAvailable() throws Exception {
        final var watermarks = Map.of("maven", Instant.ofEpochSecond(666),
                "npm", Instant.ofEpochSecond(555));

        configRegistry.setValue(CONFIG_WATERMARKS, mapper.writeValueAsString(watermarks));

        final var watermarkManager = WatermarkManager.create(configRegistry, mapper);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermarksCount()).isEqualTo(2);
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(666));
        assertThat(watermarkManager.getWatermark("npm")).isEqualTo(Instant.ofEpochSecond(555));
    }

    @Test
    void createShouldNotInitializeWatermarkWhenNotAvailable() {
        configRegistry.setValue(CONFIG_WATERMARKS, null);

        final var watermarkManager = WatermarkManager.create(configRegistry, mapper);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermarksCount()).isZero();
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsNull() {
        configRegistry.setValue(CONFIG_WATERMARKS, null);

        final var watermarkManager = WatermarkManager.create(configRegistry, mapper);

        watermarkManager.maybeAdvance("maven", Instant.ofEpochSecond(666));
        assertThat(watermarkManager.getWatermarksCount()).isZero();

        watermarkManager.maybeCommit(List.of("maven"));
        assertThat(watermarkManager.getWatermarksCount()).isEqualTo(1);
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(666));
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsEarlier() throws Exception {
        final var watermarks = Map.of("maven", Instant.ofEpochSecond(666));

        configRegistry.setValue(CONFIG_WATERMARKS, mapper.writeValueAsString(watermarks));

        final var watermarkManager = WatermarkManager.create(configRegistry, mapper);

        watermarkManager.maybeAdvance("maven", Instant.ofEpochSecond(667));
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(666));

        watermarkManager.maybeCommit(List.of("maven"));
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(667));
    }
}