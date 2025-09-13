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
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourceConfigs.CONFIG_ENABLED;
import static org.dependencytrack.datasource.vuln.nvd.NvdVulnDataSourceConfigs.CONFIG_FEEDS_URL;

class NvdVulnDataSourceTest {

    @Test
    void test() throws Exception {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_ENABLED, true);
        configRegistry.setValue(CONFIG_FEEDS_URL, URI.create("https://nvd.nist.gov/feeds").toURL());

        try (final var dataSourceFactory = new NvdVulnDataSourceFactory()) {
            dataSourceFactory.init(configRegistry);

            try (final VulnDataSource dataSource = dataSourceFactory.create()) {
                assertThat(dataSource).isNotNull();

                for (int i = 0; i < 5; i++) {
                    assertThat(dataSource.hasNext()).isTrue();

                    final Bom bom = dataSource.next();
                    assertThat(bom).isNotNull();
                    assertThat(bom.getVulnerabilitiesCount()).isEqualTo(1);

                    final Vulnerability vuln = bom.getVulnerabilities(0);
                    assertThat(vuln.getId()).startsWith("CVE-");
                    assertThat(vuln.getSource().getName()).isEqualTo("NVD");
                    assertThat(vuln.getDescription()).isNotEmpty();
                }
            }
        }
    }

}