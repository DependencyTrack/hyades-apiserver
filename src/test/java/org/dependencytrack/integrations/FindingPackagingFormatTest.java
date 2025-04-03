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
package org.dependencytrack.integrations;

import alpine.Config;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FindingPackagingFormatTest extends PersistenceCapableTest {

    @Test
    @SuppressWarnings("unchecked")
    public void wrapperTest() {
        Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, null, false);
        FindingPackagingFormat fpf = new FindingPackagingFormat(
                project.getUuid(),
                Collections.EMPTY_LIST
        );
        JSONObject root = fpf.getDocument();

        JSONObject meta = root.getJSONObject("meta");
        assertEquals(Config.getInstance().getApplicationName(), meta.getString("application"));
        assertEquals(Config.getInstance().getApplicationVersion(), meta.getString("version"));
        assertNotNull(meta.getString("timestamp"));

        JSONObject pjson = root.getJSONObject("project");
        assertEquals(project.getName(), pjson.getString("name"));
        assertEquals(project.getDescription(), pjson.getString("description"));
        assertEquals(project.getVersion(), pjson.getString("version"));
        assertEquals("1.2", root.getString("version"));
    }

    @Test
    public void testFindingsVulnerabilityAndAliases() {
        Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, null, false);

        FindingDao.FindingRow findingRow = new FindingDao.FindingRow(project.getUuid(), UUID.randomUUID(), project.getName(), project.getVersion(),
                "component-name-1", null, "component-version", null, null, UUID.randomUUID(),
                Vulnerability.Source.GITHUB, "vuln-vulnId-1", "vuln-title", "vuln-subtitle", "vuln-description",
                "vuln-recommendation", Instant.now(), Severity.CRITICAL, null, BigDecimal.valueOf(7.2), BigDecimal.valueOf(8.4),
                "cvssV2-vector", "cvssV3-vector", BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), BigDecimal.valueOf(1.3),
                "owasp-vector", null, BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9),
                AnalyzerIdentity.OSSINDEX_ANALYZER, Instant.now(), null, null, AnalysisState.NOT_AFFECTED, true, 1);
        Finding findingWithoutAlias = new Finding(findingRow);

        var alias = new VulnerabilityAlias();
        alias.setCveId("someCveId");
        alias.setSonatypeId("someSonatypeId");
        alias.setGhsaId("someGhsaId");
        alias.setOsvId("someOsvId");
        alias.setSnykId("someSnykId");
        alias.setGsdId("someGsdId");
        alias.setVulnDbId("someVulnDbId");
        alias.setInternalId("someInternalId");

        var other = new VulnerabilityAlias();
        other.setCveId("anotherCveId");
        other.setSonatypeId("anotherSonatypeId");
        other.setGhsaId("anotherGhsaId");
        other.setOsvId("anotherOsvId");
        other.setSnykId("anotherSnykId");
        other.setGsdId("anotherGsdId");
        other.setInternalId("anotherInternalId");
        other.setVulnDbId(null);

        findingRow = new FindingDao.FindingRow(project.getUuid(), UUID.randomUUID(), project.getName(), project.getVersion(),
                "component-name-2", null, "component-version", null, null, UUID.randomUUID(),
                Vulnerability.Source.NVD, "vuln-vulnId-2", "vuln-title", "vuln-subtitle", "vuln-description",
                "vuln-recommendation", Instant.now(), Severity.HIGH, null, BigDecimal.valueOf(7.2), BigDecimal.valueOf(8.4),
                "cvssV2-vector", "cvssV3-vector", BigDecimal.valueOf(1.25), BigDecimal.valueOf(1.75), BigDecimal.valueOf(1.3),
                "owasp-vector", List.of(alias, other), BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9),
                AnalyzerIdentity.INTERNAL_ANALYZER, Instant.now(), null, null, AnalysisState.NOT_AFFECTED, true, 1);
        Finding findingWithAlias = new Finding(findingRow);

        FindingPackagingFormat fpf = new FindingPackagingFormat(
                project.getUuid(),
                List.of(findingWithoutAlias, findingWithAlias)
        );

        JSONObject root = fpf.getDocument();
        JSONArray findings = root.getJSONArray("findings");

        assertEquals("component-name-1", findings.getJSONObject(0).getJSONObject("component").getString("name"));
        assertEquals("component-name-2", findings.getJSONObject(1).getJSONObject("component").getString("name"));

        assertEquals(AnalyzerIdentity.OSSINDEX_ANALYZER, findings.getJSONObject(0).getJSONObject("attribution").get("analyzerIdentity"));
        assertEquals(AnalyzerIdentity.INTERNAL_ANALYZER, findings.getJSONObject(1).getJSONObject("attribution").get("analyzerIdentity"));

        assertEquals(Severity.CRITICAL.toString(), findings.getJSONObject(0).getJSONObject("vulnerability").get("severity"));
        assertEquals(Severity.HIGH.toString(), findings.getJSONObject(1).getJSONObject("vulnerability").get("severity"));

        assertEquals(BigDecimal.valueOf(0.5), findings.getJSONObject(0).getJSONObject("vulnerability").get("epssScore"));
        assertEquals(BigDecimal.valueOf(0.9), findings.getJSONObject(1).getJSONObject("vulnerability").get("epssPercentile"));

        JSONArray aliases_1 = findings.getJSONObject(0).getJSONObject("vulnerability").getJSONArray("aliases");
        assertTrue(aliases_1.isEmpty());
        JSONArray aliases_2 = findings.getJSONObject(1).getJSONObject("vulnerability").getJSONArray("aliases");
        assertFalse(aliases_2.isEmpty());
        assertEquals(2, aliases_2.length());
        assertEquals("anotherCveId", aliases_2.getJSONObject(0).getString("cveId"));
        assertEquals("anotherGhsaId", aliases_2.getJSONObject(0).getString("ghsaId"));
        assertEquals("someCveId", aliases_2.getJSONObject(1).getString("cveId"));
        assertEquals("someOsvId", aliases_2.getJSONObject(1).getString("osvId"));

        // negative test to see if technical id is not included
        assertFalse(aliases_2.getJSONObject(0).has("id"));

        //final negative test to make sure the allBySource element is not included
        String finalJsonOutput = root.toString();
        assertFalse(finalJsonOutput.contains("allBySource"));
    }
}
