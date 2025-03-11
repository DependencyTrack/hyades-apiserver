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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.Date;
import java.util.List;

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
                "Test", "Sample project", "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("component-name-1");
        component.setVersion("component-version");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("vuln-vulnId-1");
        vulnerability.setSource(Vulnerability.Source.GITHUB);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(vulnerability, false);

        var epss = new Epss();
        epss.setCve("vuln-vulnId-1");
        epss.setScore(BigDecimal.valueOf(0.5));
        epss.setPercentile(BigDecimal.valueOf(0.9));
        qm.persist(epss);

        var attribution = new FindingAttribution();
        attribution.setComponent(component);
        attribution.setVulnerability(vulnerability);
        attribution.setAnalyzerIdentity(AnalyzerIdentity.OSSINDEX_ANALYZER);
        attribution.setAttributedOn(new Date());
        qm.persist(attribution);

        var analysis = new Analysis();
        analysis.setVulnerability(vulnerability);
        analysis.setAnalysisState(AnalysisState.NOT_AFFECTED);
        analysis.setSuppressed(true);
        qm.persist(analysis);

        Finding findingWithoutAlias = new Finding(project, component, vulnerability, epss, analysis, attribution);

        component.setName("component-name-2");
        qm.persist(component);

        vulnerability.setVulnId("vuln-vulnId-2");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        qm.persist(vulnerability);

        epss.setCve("vuln-vulnId-2");
        epss.setScore(BigDecimal.valueOf(0.5));
        epss.setPercentile(BigDecimal.valueOf(0.9));
        qm.persist(epss);

        attribution.setAnalyzerIdentity(AnalyzerIdentity.INTERNAL_ANALYZER);
        attribution.setComponent(component);
        attribution.setVulnerability(vulnerability);
        qm.persist(attribution);

        Finding findingWithAlias = new Finding(project, component, vulnerability, epss, analysis, attribution);

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

        findingWithoutAlias.addVulnerabilityAliases(List.of());
        findingWithAlias.addVulnerabilityAliases(List.of(alias, other));

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

        Assert.assertEquals(Severity.CRITICAL.toString(), findings.getJSONObject(0).getJSONObject("vulnerability").get("severity"));
        Assert.assertEquals(Severity.HIGH.toString(), findings.getJSONObject(1).getJSONObject("vulnerability").get("severity"));

        Assert.assertEquals(BigDecimal.valueOf(0.5), findings.getJSONObject(0).getJSONObject("vulnerability").get("epssScore"));
        Assert.assertEquals(BigDecimal.valueOf(0.9), findings.getJSONObject(1).getJSONObject("vulnerability").get("epssPercentile"));

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
