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

import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.generateBomFromJson;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class AbstractAdvisoryMirrorTaskTest extends PersistenceCapableTest {

    private VulnDataSource dataSourceMock;
    private CsafMirrorTask task;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        final var pluginManagerMock = mock(PluginManager.class);
        dataSourceMock = mock(VulnDataSource.class);
        doReturn(dataSourceMock).when(pluginManagerMock).getExtension(eq(VulnDataSource.class), eq("csaf"));

        task = new CsafMirrorTask(pluginManagerMock);
    }

    @Test
    public void testProcessBatchWithSingleAdvisory() throws Exception {
        // Given: A BOV with advisory metadata and a single vulnerability
        final var bovJson = """
                {
                  "properties": [
                    {
                      "name": "internal:advisory:title",
                      "value": "Test CSAF Advisory"
                    },
                    {
                      "name": "internal:advisory:name",
                      "value": "TEST-2024-001"
                    },
                    {
                      "name": "internal:advisory:version",
                      "value": "1.0.0"
                    },
                    {
                      "name": "internal:advisory:publisher:namespace",
                      "value": "https://example.com"
                    },
                    {
                      "name": "internal:advisory:url",
                      "value": "https://example.com/advisories/TEST-2024-001"
                    },
                    {
                      "name": "internal:advisory:format",
                      "value": "CSAF"
                    },
                    {
                      "name": "internal:advisory:json",
                      "value": "{\\"document\\":{\\"title\\":\\"Test\\"}}"
                    },
                    {
                      "name": "internal:advisory:updated",
                      "value": "2024-01-01T00:00:00Z"
                    }
                  ],
                  "components": [
                    {
                      "bomRef": "comp-001",
                      "type": "CLASSIFICATION_APPLICATION",
                      "name": "test-component",
                      "version": "1.0.0"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "CSAF-CVE-2024-12345",
                      "source": { "name": "CSAF" },
                      "description": "Test vulnerability",
                      "published": "2024-01-01T00:00:00Z",
                      "updated": "2024-01-01T00:00:00Z",
                      "ratings": [
                        {
                          "method": "SCORE_METHOD_CVSSV31",
                          "score": 7.5,
                          "severity": "SEVERITY_HIGH"
                        }
                      ],
                      "affects": [
                        {
                          "ref": "comp-001"
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        // When: Processing the batch
        task.processBatch(dataSourceMock, List.of(bov));

        // Then: Advisory should be created and persisted
        try (var qm = new QueryManager(); final var query = qm.getPersistenceManager().newQuery(Advisory.class)) {
            @SuppressWarnings("unchecked")
            final List<Advisory> advisories = (List<Advisory>) query.execute();
            assertThat(advisories).hasSize(1);

            final Advisory advisory = advisories.getFirst();
            assertThat(advisory.getTitle()).isEqualTo("Test CSAF Advisory");
            assertThat(advisory.getName()).isEqualTo("TEST-2024-001");
            assertThat(advisory.getVersion()).isEqualTo("1.0.0");
            assertThat(advisory.getPublisher()).isEqualTo("https://example.com");
            assertThat(advisory.getUrl()).isEqualTo("https://example.com/advisories/TEST-2024-001");
            assertThat(advisory.getFormat()).isEqualTo("CSAF");
            assertThat(advisory.getContent()).contains("\"title\":\"Test\"");
            assertThat(advisory.getLastFetched()).isNotNull();

            // Verify vulnerability was synchronized and associated
            assertThat(advisory.getVulnerabilities()).hasSize(1);
            final Vulnerability vuln = advisory.getVulnerabilities().getFirst();
            assertThat(vuln.getVulnId()).containsIgnoringCase("CVE-2024-12345");
            assertThat(vuln.getSource()).isEqualTo("CSAF");
        }

        // Verify the BOV was marked as processed
        verify(dataSourceMock, times(1)).markProcessed(eq(bov));
    }

}
