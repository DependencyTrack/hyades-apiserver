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
 * Copyright (c) Steve Springett. All Rights Reserved.
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class FindingPackagingFormatTest extends PersistenceCapableTest {

    @Test
    @SuppressWarnings("unchecked")
    public void wrapperTest() {
        Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, true, false);
        FindingPackagingFormat fpf = new FindingPackagingFormat(
                project.getUuid(),
                Collections.EMPTY_LIST
        );
        JSONObject root = fpf.getDocument();

        JSONObject meta = root.getJSONObject("meta");
        Assert.assertEquals(Config.getInstance().getApplicationName(), meta.getString("application"));
        Assert.assertEquals(Config.getInstance().getApplicationVersion(), meta.getString("version"));
        Assert.assertNotNull(meta.getString("timestamp"));

        JSONObject pjson = root.getJSONObject("project");
        Assert.assertEquals(project.getName(), pjson.getString("name"));
        Assert.assertEquals(project.getDescription(), pjson.getString("description"));
        Assert.assertEquals(project.getVersion(), pjson.getString("version"));
        Assert.assertEquals("1.2", root.getString("version"));
    }

    @Test
    public void testFindingsVulnerabilityAndAliases() {
        Project project = qm.createProject(
                "Test", "Sample project", "1.0", null, null, null, true, false);

        final var componentA = new Finding.Component();
        componentA.setProject(project.getUuid());
        componentA.setUuid(UUID.randomUUID());
        componentA.setGroup("component-group");
        componentA.setName("component-name-1");
        componentA.setVersion("component-version");
        componentA.setCpe("component-cpe");
        componentA.setPurl("component-purl");
        final var vulnA = new Finding.Vulnerability();
        vulnA.setUuid(UUID.randomUUID());
        vulnA.setVulnId("vuln-vulnId-1");
        vulnA.setSource(Vulnerability.Source.GITHUB);
        vulnA.setTitle("vuln-title");
        vulnA.setSubtitle("vuln-subtitle");
        vulnA.setDescription("vuln-description");
        vulnA.setRecommendation("vuln-recommendation");
        vulnA.setSeverity(Severity.CRITICAL);
        vulnA.setCvssV2BaseScore(7.2);
        vulnA.setCvssV3BaseScore(8.4);
        vulnA.setOwaspLikelihoodScore(1.25);
        vulnA.setOwaspBusinessImpactScore(1.75);
        vulnA.setOwaspTechnicalImpactScore(1.3);
        vulnA.setEpssScore(0.5);
        vulnA.setEpssPercentile(0.9);
        final var attributionA = new Finding.Attribution();
        attributionA.setAnalyzerIdentity(AnalyzerIdentity.OSSINDEX_ANALYZER);
        attributionA.setAttributedOn(new Date());
        final var analysisA = new Finding.Analysis();
        analysisA.setState(AnalysisState.NOT_AFFECTED);
        analysisA.setSuppressed(true);
        Finding findingWithoutAlias = new Finding(analysisA, attributionA, componentA, vulnA);

        final var componentB = new Finding.Component();
        componentB.setProject(project.getUuid());
        componentB.setUuid(UUID.randomUUID());
        componentB.setGroup("component-group");
        componentB.setName("component-name-2");
        componentB.setVersion("component-version");
        componentB.setCpe("component-cpe");
        componentB.setPurl("component-purl");
        final var vulnB = new Finding.Vulnerability();
        vulnB.setUuid(UUID.randomUUID());
        vulnB.setVulnId("vuln-vulnId-2");
        vulnB.setSource(Vulnerability.Source.NVD);
        vulnB.setTitle("vuln-title");
        vulnB.setSubtitle("vuln-subtitle");
        vulnB.setDescription("vuln-description");
        vulnB.setRecommendation("vuln-recommendation");
        vulnB.setSeverity(Severity.HIGH);
        vulnB.setCvssV2BaseScore(7.2);
        vulnB.setCvssV3BaseScore(8.4);
        vulnB.setOwaspLikelihoodScore(1.25);
        vulnB.setOwaspBusinessImpactScore(1.75);
        vulnB.setOwaspTechnicalImpactScore(1.3);
        vulnB.setEpssScore(0.5);
        vulnB.setEpssPercentile(0.9);
        final var attributionB = new Finding.Attribution();
        attributionB.setAnalyzerIdentity(AnalyzerIdentity.INTERNAL_ANALYZER);
        attributionB.setAttributedOn(new Date());
        final var analysisB = new Finding.Analysis();
        analysisB.setState(AnalysisState.NOT_AFFECTED);
        analysisB.setSuppressed(true);
        Finding findingWithAlias = new Finding(analysisB, attributionB, componentB, vulnB);

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

        findingWithoutAlias.getVulnerability().addVulnerabilityAliases(List.of());
        findingWithAlias.getVulnerability().addVulnerabilityAliases(List.of(alias, other));

        FindingPackagingFormat fpf = new FindingPackagingFormat(
                project.getUuid(),
                List.of(findingWithoutAlias, findingWithAlias)
        );

        JSONObject root = fpf.getDocument();

        JSONArray findings = root.getJSONArray("findings");

        Assert.assertEquals("component-name-1", findings.getJSONObject(0).getJSONObject("component").getString("name"));
        Assert.assertEquals("component-name-2", findings.getJSONObject(1).getJSONObject("component").getString("name"));

        Assert.assertEquals(AnalyzerIdentity.OSSINDEX_ANALYZER, findings.getJSONObject(0).getJSONObject("attribution").get("analyzerIdentity"));
        Assert.assertEquals(AnalyzerIdentity.INTERNAL_ANALYZER, findings.getJSONObject(1).getJSONObject("attribution").get("analyzerIdentity"));

        Assert.assertEquals(Severity.CRITICAL, findings.getJSONObject(0).getJSONObject("vulnerability").get("severity"));
        Assert.assertEquals(Severity.HIGH, findings.getJSONObject(1).getJSONObject("vulnerability").get("severity"));

        JSONArray aliases_1 = findings.getJSONObject(0).getJSONObject("vulnerability").getJSONArray("aliases");
        Assert.assertTrue(aliases_1.isEmpty());
        JSONArray aliases_2 = findings.getJSONObject(1).getJSONObject("vulnerability").getJSONArray("aliases");
        Assert.assertFalse(aliases_2.isEmpty());
        Assert.assertEquals(2, aliases_2.length());
        Assert.assertEquals("anotherCveId", aliases_2.getJSONObject(0).getString("cveId"));
        Assert.assertEquals("anotherGhsaId", aliases_2.getJSONObject(0).getString("ghsaId"));
        Assert.assertEquals("someCveId", aliases_2.getJSONObject(1).getString("cveId"));
        Assert.assertEquals("someOsvId", aliases_2.getJSONObject(1).getString("osvId"));

        // negative test to see if technical id is not included
        Assert.assertFalse(aliases_2.getJSONObject(0).has("id"));

        //final negative test to make sure the allBySource element is not included
        String finalJsonOutput = root.toString();
        Assert.assertFalse(finalJsonOutput.contains("allBySource"));
    }

}
