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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.Assert.assertEquals;

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
        Assert.assertNotNull(meta.getString("timestamp"));

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
        var finding1 = (Finding) findings.get(0);
        var finding2 = (Finding) findings.get(1);
        assertEquals("component-name-1", finding1.getComponent().get("name"));
        assertEquals("component-name-2", finding2.getComponent().get("name"));

        assertEquals(AnalyzerIdentity.OSSINDEX_ANALYZER, finding1.getAttribution().get("analyzerIdentity"));
        assertEquals(AnalyzerIdentity.INTERNAL_ANALYZER, finding2.getAttribution().get("analyzerIdentity"));

        assertEquals(Severity.CRITICAL.toString(), finding1.getVulnerability().get("severity"));
        assertEquals(Severity.HIGH.toString(), finding2.getVulnerability().get("severity"));

        assertEquals(BigDecimal.valueOf(0.5), finding1.getVulnerability().get("epssScore"));
        assertEquals(BigDecimal.valueOf(0.9), finding2.getVulnerability().get("epssPercentile"));

        var aliases_1 = (HashSet) finding1.getVulnerability().get("aliases");
        Assert.assertTrue(aliases_1.isEmpty());
        var aliases_2 = (Set<Map<String, String>>) finding2.getVulnerability().get("aliases");
        Assert.assertFalse(aliases_2.isEmpty());
        assertEquals(2, aliases_2.size());

        var alias_1 = aliases_2.stream().toList().get(0);
        var alias_2 = aliases_2.stream().toList().get(1);
        Assert.assertEquals("anotherCveId", alias_1.get("cveId"));
        Assert.assertEquals("anotherGhsaId", alias_1.get("ghsaId"));
        Assert.assertEquals("someCveId", alias_2.get("cveId"));
        Assert.assertEquals("someOsvId", alias_2.get("osvId"));

        // negative test to see if technical id is not included
        assertThat(alias_1.get("id")).isNull();

        //final negative test to make sure the allBySource element is not included
        String finalJsonOutput = root.toString();
        Assert.assertFalse(finalJsonOutput.contains("allBySource"));
    }
}
