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
package org.dependencytrack.datasource.vuln.nvd;

import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class NvdVulnDataSourceTest {

    @Test
    @Disabled
    void test() {
        final ConfigRegistry configRegistry = new MockConfigRegistry();
        configRegistry.setValue(NvdVulnDataSourceConfigs.CONFIG_FEEDS_URL, "https://nvd.nist.gov/feeds");

        try (final var dataSourceFactory = new NvdVulnDataSourceFactory()) {
            dataSourceFactory.init(configRegistry);

            try (final VulnDataSource dataSource = dataSourceFactory.create()) {
                while (dataSource.hasNext()) {
                    final Bom bov = dataSource.next();
                    Assertions.assertNotNull(bov);
                }
            }
        }
    }

}