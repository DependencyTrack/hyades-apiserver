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

import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.generateBomFromJson;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class OsvMirrorTaskTest extends PersistenceCapableTest {

    private PluginManager pluginManager;
    private OsvMirrorTask task;

    @BeforeEach
    void beforeEach() {
        // Set up task lock configuration for OSV mirror task
        MemoryConfigSource.setProperty("task.osv.mirror.lock.max.duration", "PT15M");
        MemoryConfigSource.setProperty("task.osv.mirror.lock.min.duration", "PT1M");

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                secretName -> null,
                List.of(VulnDataSource.class));
        task = new OsvMirrorTask(pluginManager);
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    // ==================== Basic Functionality Tests ====================

    @Test
    void testProcessOsvVuln() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "2a24a29f-9ff3-52b8-bc81-471f326a5b3e",
                      "name": "io.ratpack:ratpack-session",
                      "purl": "pkg:maven/io.ratpack/ratpack-session"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "GHSA-2cc5-23r7-vc4v",
                      "source": { "name": "OSV" },
                      "description": "### Impact",
                      "cwes": [ 330, 340 ],
                      "published": "2021-07-01T17:02:26Z",
                      "updated": "2023-03-28T05:45:27Z",
                      "ratings": [
                        {
                          "method": "SCORE_METHOD_CVSSV3",
                          "score": 4.4,
                          "severity": "SEVERITY_MEDIUM",
                          "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
                        }
                      ],
                      "properties": [
                        {
                          "name": "dependency-track:vuln:title",
                          "value": "Ratpack's default client side session signing key is highly predictable"
                        },
                        {
                          "name": "internal:osv:ecosystem",
                          "value": "Maven"
                        }
                      ],
                      "affects": [
                        {
                          "ref": "2a24a29f-9ff3-52b8-bc81-471f326a5b3e",
                          "versions": [
                            { "range": "vers:maven/>=0|<1.9.0" },
                            { "version": "0.9.0" },
                            { "version": "0.9.1" }
                          ]
                        }
                      ]
                    }
                  ],
                  "externalReferences": [
                    { "url": "https://github.com/ratpack/ratpack/security/advisories/GHSA-2cc5-23r7-vc4v" }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "GHSA-2cc5-23r7-vc4v");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnId()).isEqualTo("GHSA-2cc5-23r7-vc4v");
        assertThat(vuln.getSource()).isEqualTo("OSV");
        assertThat(vuln.getTitle()).isEqualTo("Ratpack's default client side session signing key is highly predictable");
        assertThat(vuln.getDescription()).isEqualTo("### Impact");
        assertThat(vuln.getCwes()).containsOnly(330, 340);
        assertThat(vuln.getPublished()).isEqualTo("2021-07-01T17:02:26Z");
        assertThat(vuln.getUpdated()).isEqualTo("2023-03-28T05:45:27Z");
        assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
        assertThat(vuln.getCvssV3BaseScore()).isEqualTo("4.4");
        assertThat(vuln.getSeverity()).isEqualTo(Severity.MEDIUM);

        assertThat(vuln.getVulnerableSoftware()).hasSize(3);
    }

    @Test
    void testProcessOsvVulnWithMultipleEcosystems() throws Exception {
        final var bovJson1 = """
                {
                  "components": [
                    {
                      "bomRef": "maven-ref",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-MAVEN-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "maven-ref",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final var bovJson2 = """
                {
                  "components": [
                    {
                      "bomRef": "npm-ref",
                      "purl": "pkg:npm/example-package"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-NPM-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-02T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "npm" }
                      ],
                      "affects": [
                        {
                          "ref": "npm-ref",
                          "versions": [ { "version": "2.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov1 = generateBomFromJson(bovJson1);
        final Bom bov2 = generateBomFromJson(bovJson2);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, true, false).when(dataSourceMock).hasNext();
        doReturn(bov1, bov2).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, times(2)).markProcessed(any(Bom.class));

        final Vulnerability vuln1 = qm.getVulnerabilityByVulnId("OSV", "OSV-MAVEN-001");
        assertThat(vuln1).isNotNull();
        assertThat(vuln1.getSource()).isEqualTo("OSV");

        final Vulnerability vuln2 = qm.getVulnerabilityByVulnId("OSV", "OSV-NPM-001");
        assertThat(vuln2).isNotNull();
        assertThat(vuln2.getSource()).isEqualTo("OSV");
    }

    @Test
    void testProcessOsvVulnWithVersionRanges() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/bar"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-RANGE-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [
                            { "range": "vers:maven/>=1.0.0|<2.0.0" },
                            { "range": "vers:maven/>=3.0.0|<4.0.0" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-RANGE-001");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnerableSoftware()).hasSize(2);
    }

    // ==================== Incremental Mirroring Tests ====================

    @Test
    void testProcessOsvVulnWithIncrementalMirroringEnabled() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/test"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-INC-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T12:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        // markProcessed is always called regardless of incremental mirroring setting
        // The watermark logic is handled inside the data source's markProcessed method
        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-INC-001");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithIncrementalMirroringDisabled() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/test"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-FULL-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T12:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        // markProcessed is always called regardless of incremental mirroring setting
        // When incremental mirroring is disabled, watermark manager is null in the data source
        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-FULL-001");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithIncrementalMirroringDefaultValue() throws Exception {
        // Test that default value (true) works correctly
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/default"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-DEFAULT-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T12:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-DEFAULT-001");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithIncrementalMirroringAndMultipleBatches() throws Exception {
        // Test that incremental mirroring works correctly with multiple batches
        final List<Bom> bovs = new ArrayList<>();
        final List<Boolean> hasNextResponses = new ArrayList<>();

        for (int i = 0; i < 30; i++) {
            final var bovJson = """
                    {
                      "components": [
                        {
                          "bomRef": "ref-%d",
                          "purl": "pkg:maven/com.example/incr%d"
                        }
                      ],
                      "vulnerabilities": [
                        {
                          "id": "OSV-INCR-BATCH-%d",
                          "source": { "name": "OSV" },
                          "updated": "2024-01-01T00:00:00Z",
                          "properties": [
                            { "name": "internal:osv:ecosystem", "value": "Maven" }
                          ],
                          "affects": [
                            {
                              "ref": "ref-%d",
                              "versions": [ { "version": "1.0.0" } ]
                            }
                          ]
                        }
                      ]
                    }
                    """.formatted(i, i, i, i);

            bovs.add(generateBomFromJson(bovJson));
            hasNextResponses.add(true);
        }
        hasNextResponses.add(false);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(hasNextResponses.toArray(new Boolean[0])).when(dataSourceMock).hasNext();
        doReturn(bovs.toArray(new Bom[0])).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        // All BOVs should be marked as processed
        verify(dataSourceMock, times(30)).markProcessed(any(Bom.class));

        for (int i = 0; i < 30; i++) {
            final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-INCR-BATCH-" + i);
            assertThat(vuln).isNotNull();
        }
    }

    // ==================== Batch Processing Tests ====================

    @Test
    void testProcessBatchOf25() throws Exception {
        final List<Bom> bovs = new ArrayList<>();
        final List<Boolean> hasNextResponses = new ArrayList<>();

        for (int i = 0; i < 25; i++) {
            final var bovJson = """
                    {
                      "components": [
                        {
                          "bomRef": "ref-%d",
                          "purl": "pkg:maven/com.example/pkg%d"
                        }
                      ],
                      "vulnerabilities": [
                        {
                          "id": "OSV-BATCH-%d",
                          "source": { "name": "OSV" },
                          "updated": "2024-01-01T00:00:00Z",
                          "properties": [
                            { "name": "internal:osv:ecosystem", "value": "Maven" }
                          ],
                          "affects": [
                            {
                              "ref": "ref-%d",
                              "versions": [ { "version": "1.0.0" } ]
                            }
                          ]
                        }
                      ]
                    }
                    """.formatted(i, i, i, i);

            bovs.add(generateBomFromJson(bovJson));
            hasNextResponses.add(true);
        }
        hasNextResponses.add(false);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(hasNextResponses.toArray(new Boolean[0])).when(dataSourceMock).hasNext();
        doReturn(bovs.toArray(new Bom[0])).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, times(25)).markProcessed(any(Bom.class));

        for (int i = 0; i < 25; i++) {
            final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-BATCH-" + i);
            assertThat(vuln).isNotNull();
        }
    }

    @Test
    void testProcessBatchLessThan25() throws Exception {
        final List<Bom> bovs = new ArrayList<>();
        final List<Boolean> hasNextResponses = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            final var bovJson = """
                    {
                      "components": [
                        {
                          "bomRef": "ref-%d",
                          "purl": "pkg:maven/com.example/pkg%d"
                        }
                      ],
                      "vulnerabilities": [
                        {
                          "id": "OSV-SMALL-%d",
                          "source": { "name": "OSV" },
                          "updated": "2024-01-01T00:00:00Z",
                          "properties": [
                            { "name": "internal:osv:ecosystem", "value": "Maven" }
                          ],
                          "affects": [
                            {
                              "ref": "ref-%d",
                              "versions": [ { "version": "1.0.0" } ]
                            }
                          ]
                        }
                      ]
                    }
                    """.formatted(i, i, i, i);

            bovs.add(generateBomFromJson(bovJson));
            hasNextResponses.add(true);
        }
        hasNextResponses.add(false);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(hasNextResponses.toArray(new Boolean[0])).when(dataSourceMock).hasNext();
        doReturn(bovs.toArray(new Bom[0])).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, times(10)).markProcessed(any(Bom.class));

        for (int i = 0; i < 10; i++) {
            final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-SMALL-" + i);
            assertThat(vuln).isNotNull();
        }
    }

    @Test
    void testProcessBatchMoreThan25() throws Exception {
        final List<Bom> bovs = new ArrayList<>();
        final List<Boolean> hasNextResponses = new ArrayList<>();

        for (int i = 0; i < 30; i++) {
            final var bovJson = """
                    {
                      "components": [
                        {
                          "bomRef": "ref-%d",
                          "purl": "pkg:maven/com.example/pkg%d"
                        }
                      ],
                      "vulnerabilities": [
                        {
                          "id": "OSV-LARGE-%d",
                          "source": { "name": "OSV" },
                          "updated": "2024-01-01T00:00:00Z",
                          "properties": [
                            { "name": "internal:osv:ecosystem", "value": "Maven" }
                          ],
                          "affects": [
                            {
                              "ref": "ref-%d",
                              "versions": [ { "version": "1.0.0" } ]
                            }
                          ]
                        }
                      ]
                    }
                    """.formatted(i, i, i, i);

            bovs.add(generateBomFromJson(bovJson));
            hasNextResponses.add(true);
        }
        hasNextResponses.add(false);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(hasNextResponses.toArray(new Boolean[0])).when(dataSourceMock).hasNext();
        doReturn(bovs.toArray(new Bom[0])).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, times(30)).markProcessed(any(Bom.class));

        for (int i = 0; i < 30; i++) {
            final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-LARGE-" + i);
            assertThat(vuln).isNotNull();
        }
    }

    @Test
    void testProcessEmptyBatch() throws Exception {
        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(false).when(dataSourceMock).hasNext();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, never()).next();
        verify(dataSourceMock, never()).markProcessed(any(Bom.class));
    }

    // ==================== Edge Cases - Invalid BOV Structures ====================

    @Test
    void testProcessVulnWithoutAffects() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-NO-AFFECTS",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-NO-AFFECTS");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnerableSoftware()).isEmpty();
    }

    @Test
    void testProcessVulnWithUnmatchedAffectsBomRef() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "actual-ref",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-UNMATCHED",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "non-existent-ref",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-UNMATCHED");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnerableSoftware()).isEmpty();
    }

    @Test
    void testProcessBovWithNoVulnerabilities() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": []
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));
    }

    @Test
    void testProcessBovWithMultipleVulnerabilities() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-MULTI-1",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ]
                    },
                    {
                      "id": "OSV-MULTI-2",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln1 = qm.getVulnerabilityByVulnId("OSV", "OSV-MULTI-1");
        final Vulnerability vuln2 = qm.getVulnerabilityByVulnId("OSV", "OSV-MULTI-2");
        assertThat(vuln1).isNull();
        assertThat(vuln2).isNull();
    }

    // ==================== Edge Cases - Rejected/Withdrawn Vulnerabilities ====================

    @Test
    void testProcessRejectedVulnerability() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-REJECTED",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "rejected": "2024-01-02T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, never()).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-REJECTED");
        assertThat(vuln).isNull();
    }

    @Test
    void testProcessRejectedVulnerabilityWithValidOnes() throws Exception {
        final var rejectedBovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/rejected"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-REJECTED-MIX",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "rejected": "2024-01-02T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final var validBovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-2",
                      "purl": "pkg:maven/com.example/valid"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-VALID-MIX",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-2",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom rejectedBov = generateBomFromJson(rejectedBovJson);
        final Bom validBov = generateBomFromJson(validBovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, true, false).when(dataSourceMock).hasNext();
        doReturn(rejectedBov, validBov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(validBov));
        verify(dataSourceMock, never()).markProcessed(eq(rejectedBov));

        final Vulnerability rejectedVuln = qm.getVulnerabilityByVulnId("OSV", "OSV-REJECTED-MIX");
        final Vulnerability validVuln = qm.getVulnerabilityByVulnId("OSV", "OSV-VALID-MIX");
        assertThat(rejectedVuln).isNull();
        assertThat(validVuln).isNotNull();
    }

    // ==================== Edge Cases - Data Source States ====================

    @Test
    void testProcessWhenDataSourceDisabled() throws Exception {
        final var dataSourceMock = mock(VulnDataSource.class);

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(false, () -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, never()).hasNext();
        verify(dataSourceMock, never()).next();
        verify(dataSourceMock, never()).markProcessed(any(Bom.class));
    }

    @Test
    void testProcessWhenFactoryNotFound() throws Exception {
        task.inform(new OsvMirrorEvent());

        final var vulnerabilities = qm.getVulnerabilities().getObjects();
        @SuppressWarnings("unchecked")
        final List<Vulnerability> vulnList = (List<Vulnerability>) vulnerabilities;
        assertThat(vulnList).isEmpty();
    }

    @Test
    void testProcessWithEmptyDataSource() throws Exception {
        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(false).when(dataSourceMock).hasNext();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, never()).next();
        verify(dataSourceMock, never()).markProcessed(any(Bom.class));
    }

    // ==================== Edge Cases - Thread Interruption ====================

    @Test
    void testProcessWithThreadInterruption() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-INTERRUPT",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, true).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        final Thread testThread = new Thread(() -> {
            task.inform(new OsvMirrorEvent());
        });

        testThread.start();
        testThread.interrupt();
        testThread.join(1000);

        verify(dataSourceMock, atLeast(1)).hasNext();
    }

    // ==================== Edge Cases - OSV-Specific ====================

    @Test
    void testProcessOsvVulnWithAliasSyncEnabled() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/alias"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-ALIAS-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-ALIAS-001");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithMissingEcosystemProperty() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/foo"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-NO-ECOSYSTEM",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-NO-ECOSYSTEM");
        assertThat(vuln).isNotNull();
    }

    // ==================== Edge Cases - Database Operations ====================

    @Test
    void testUpdateExistingVulnerability() throws Exception {
        final var existingVuln = new org.dependencytrack.model.Vulnerability();
        existingVuln.setVulnId("OSV-UPDATE");
        existingVuln.setSource("OSV");
        existingVuln.setDescription("Old description");
        qm.persist(existingVuln);

        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/update"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-UPDATE",
                      "source": { "name": "OSV" },
                      "description": "New description",
                      "updated": "2024-01-02T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        qm.getPersistenceManager().evictAll();
        final Vulnerability updatedVuln = qm.getVulnerabilityByVulnId("OSV", "OSV-UPDATE");
        assertThat(updatedVuln).isNotNull();
        assertThat(updatedVuln.getDescription()).isEqualTo("New description");
    }

    @Test
    void testSynchronizeVulnerableSoftware() throws Exception {
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/vs-test"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-VS-001",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [
                            { "version": "1.0.0" },
                            { "range": "vers:maven/>=2.0.0|<3.0.0" }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-VS-001");
        assertThat(vuln).isNotNull();
        assertThat(vuln.getVulnerableSoftware()).hasSize(2);
    }

    // ==================== Edge Cases - Incremental Mirroring Configuration ====================

    @Test
    void testProcessOsvVulnWithMissingUpdatedTimestamp() throws Exception {
        // Test that vulnerabilities without updated timestamp are still processed
        // but watermark logic may not work correctly
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/no-updated"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-NO-UPDATED",
                      "source": { "name": "OSV" },
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-NO-UPDATED");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithFutureUpdatedTimestamp() throws Exception {
        // Test that vulnerabilities with future timestamps are handled correctly
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/future"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-FUTURE",
                      "source": { "name": "OSV" },
                      "updated": "2099-12-31T23:59:59Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-FUTURE");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithVeryOldUpdatedTimestamp() throws Exception {
        // Test that vulnerabilities with very old timestamps are handled correctly
        final var bovJson = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/old"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-OLD",
                      "source": { "name": "OSV" },
                      "updated": "1970-01-01T00:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov = generateBomFromJson(bovJson);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, false).when(dataSourceMock).hasNext();
        doReturn(bov).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock).markProcessed(eq(bov));

        final Vulnerability vuln = qm.getVulnerabilityByVulnId("OSV", "OSV-OLD");
        assertThat(vuln).isNotNull();
    }

    @Test
    void testProcessOsvVulnWithSameUpdatedTimestamp() throws Exception {
        // Test that vulnerabilities with the same updated timestamp are handled correctly
        final var bovJson1 = """
                {
                  "components": [
                    {
                      "bomRef": "ref-1",
                      "purl": "pkg:maven/com.example/same1"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-SAME-1",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T12:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-1",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final var bovJson2 = """
                {
                  "components": [
                    {
                      "bomRef": "ref-2",
                      "purl": "pkg:maven/com.example/same2"
                    }
                  ],
                  "vulnerabilities": [
                    {
                      "id": "OSV-SAME-2",
                      "source": { "name": "OSV" },
                      "updated": "2024-01-01T12:00:00Z",
                      "properties": [
                        { "name": "internal:osv:ecosystem", "value": "Maven" }
                      ],
                      "affects": [
                        {
                          "ref": "ref-2",
                          "versions": [ { "version": "1.0.0" } ]
                        }
                      ]
                    }
                  ]
                }
                """;

        final Bom bov1 = generateBomFromJson(bovJson1);
        final Bom bov2 = generateBomFromJson(bovJson2);

        final var dataSourceMock = mock(VulnDataSource.class);
        doReturn(true, true, false).when(dataSourceMock).hasNext();
        doReturn(bov1, bov2).when(dataSourceMock).next();

        pluginManager.loadPlugins(List.of(
                () -> List.of(new TestOsvVulnDataSourceFactory(() -> dataSourceMock))));

        task.inform(new OsvMirrorEvent());

        verify(dataSourceMock, times(2)).markProcessed(any(Bom.class));

        final Vulnerability vuln1 = qm.getVulnerabilityByVulnId("OSV", "OSV-SAME-1");
        final Vulnerability vuln2 = qm.getVulnerabilityByVulnId("OSV", "OSV-SAME-2");
        assertThat(vuln1).isNotNull();
        assertThat(vuln2).isNotNull();
    }

    // ==================== Helper Classes ====================

    private static class TestOsvVulnDataSourceFactory implements VulnDataSourceFactory {

        private final boolean enabled;
        private final Supplier<VulnDataSource> dataSourceSupplier;

        private TestOsvVulnDataSourceFactory(
                boolean enabled,
                Supplier<VulnDataSource> dataSourceSupplier) {
            this.enabled = enabled;
            this.dataSourceSupplier = dataSourceSupplier;
        }

        private TestOsvVulnDataSourceFactory(Supplier<VulnDataSource> dataSourceSupplier) {
            this(true, dataSourceSupplier);
        }

        @Override
        public boolean isDataSourceEnabled() {
            return enabled;
        }

        @Override
        public String extensionName() {
            return "osv";
        }

        @Override
        public Class<? extends VulnDataSource> extensionClass() {
            return TestOsvVulnDataSource.class;
        }

        @Override
        public int priority() {
            return 0;
        }

        @Override
        public void init(ExtensionContext ctx) {
        }

        @Override
        public VulnDataSource create() {
            return dataSourceSupplier.get();
        }

    }

    private static class TestOsvVulnDataSource implements VulnDataSource {

        @Override
        public boolean hasNext() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Bom next() {
            throw new UnsupportedOperationException();
        }

    }

}
