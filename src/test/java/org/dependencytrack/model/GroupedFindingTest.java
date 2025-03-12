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
package org.dependencytrack.model;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.Date;
import java.util.Map;

public class GroupedFindingTest extends PersistenceCapableTest {
    private Date published = new Date();

    private GroupedFinding groupedFinding;

    @Before
    public void setUp() {
        groupedFinding = createTestFinding();
    }

    @Test
    public void testVulnerability() {
        Map map = groupedFinding.getVulnerability();
        Assert.assertEquals("vuln-source", map.get("source"));
        Assert.assertEquals("vuln-vulnId", map.get("vulnId"));
        Assert.assertEquals("vuln-title", map.get("title"));
        Assert.assertEquals(Severity.HIGH, map.get("severity"));
        Assert.assertEquals(published, map.get("published"));
        Assert.assertEquals(BigDecimal.valueOf(8.5), map.get("cvssV2BaseScore"));
        Assert.assertEquals(BigDecimal.valueOf(8.4), map.get("cvssV3BaseScore"));
        Assert.assertEquals(3, map.get("affectedProjectCount"));
    }

    @Test
    public void testAttribution() {
        Map map = groupedFinding.getAttribution();
        Assert.assertEquals(AnalyzerIdentity.INTERNAL_ANALYZER, map.get("analyzerIdentity"));
    }

    private GroupedFinding createTestFinding() {
        final var project = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("component-name");
        component.setVersion("component-version");
        component.setGroup("component-group");
        component.setPurl("pkg:maven/foo/bar@1.2.3");
        component.setCpe("component-cpe");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("vuln-vulnId");
        vulnerability.setSource("vuln-source");
        vulnerability.setTitle("vuln-title");
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setCvssV2BaseScore(BigDecimal.valueOf(8.5));
        vulnerability.setCvssV3BaseScore(BigDecimal.valueOf(8.4));
        vulnerability.setPublished(published);
        vulnerability.setAffectedProjectCount(3);
        qm.createVulnerability(vulnerability, false);

        var attribution = new FindingAttribution();
        attribution.setComponent(component);
        attribution.setVulnerability(vulnerability);
        attribution.setAnalyzerIdentity(AnalyzerIdentity.INTERNAL_ANALYZER);
        attribution.setAttributedOn(new Date());
        qm.persist(attribution);

        return new GroupedFinding(vulnerability, attribution);
    }
}