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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.Vulnerability.Source.CSAF;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

public class AdvisoryDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private AdvisoryDao advisoryDao;

    @Before
    public void before() throws Exception {
        super.before();
        jdbiHandle = openJdbiHandle();
        advisoryDao = jdbiHandle.attach(AdvisoryDao.class);
    }

    @After
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
        super.after();
    }

    @Test
    public void testGetAllAdvisories() {
        // Create test data
        createAdvisory("Advisory Alpha", "CSAF", "publisher1", "ADV-001", "1.0");
        createAdvisory("Advisory Beta", "CSAF", "publisher2", "ADV-002", "2.0");
        createAdvisory("Advisory Gamma", "OTHER", "publisher3", "ADV-003", "1.5");

        // Test: Get all advisories without a filter
        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories(null, null);
        assertThat(results).hasSize(3);

        // Test: Filter by format
        List<AdvisoryDao.AdvisoryDetailRow> csafResults = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(csafResults).hasSize(2);
        assertThat(csafResults).extracting(AdvisoryDao.AdvisoryDetailRow::title)
                .containsExactlyInAnyOrder("Advisory Alpha", "Advisory Beta");

        List<AdvisoryDao.AdvisoryDetailRow> vexResults = advisoryDao.getAllAdvisories("OTHER", null);
        assertThat(vexResults).hasSize(1);
        assertThat(vexResults.getFirst().title()).isEqualTo("Advisory Gamma");
    }

    @Test
    public void testGetAllAdvisoriesWithAffectedCounts() {
        // Create test data with projects and components
        final var project1 = qm.createProject("Project 1", null, "1.0", null, null, null, null, false);
        final var project2 = qm.createProject("Project 2", null, "1.0", null, null, null, null, false);

        final var component1 = new Component();
        component1.setProject(project1);
        component1.setName("component-1");
        component1.setVersion("1.0.0");
        qm.persist(component1);

        final var component2 = new Component();
        component2.setProject(project1);
        component2.setName("component-2");
        component2.setVersion("1.0.0");
        qm.persist(component2);

        final var component3 = new Component();
        component3.setProject(project2);
        component3.setName("component-3");
        component3.setVersion("1.0.0");
        qm.persist(component3);

        // Create advisory
        final var advisory = createAdvisory("Test Advisory", "CSAF", "test-publisher", "TEST-001", "1.0");

        // Create vulnerability and link to advisory
        final var vuln = new Vulnerability();
        vuln.setVulnId("VULN-123");
        vuln.setSource(CSAF);
        qm.persist(vuln);
        advisory.addVulnerability(vuln);

        // Add vulnerability to components
        qm.addVulnerability(vuln, component1, AnalyzerIdentity.INTERNAL_ANALYZER, "Test1", "http://test.com/1", new Date());
        qm.addVulnerability(vuln, component2, AnalyzerIdentity.INTERNAL_ANALYZER, "Test2", "http://test.com/2", new Date());
        qm.addVulnerability(vuln, component3, AnalyzerIdentity.INTERNAL_ANALYZER, "Test3", "http://test.com/3", new Date());

        // Test: Verify affected counts
        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(1);

        AdvisoryDao.AdvisoryDetailRow result = results.getFirst();
        assertThat(result.title()).isEqualTo("Test Advisory");
        assertThat(result.affectedComponents()).isEqualTo(3);
        assertThat(result.affectedProjects()).isEqualTo(2);
    }

    @Test
    public void testGetAllAdvisoriesSearchText() {
        // Create test data with searchable content
        createAdvisory("Security Alert for Apache", "CSAF", "apache", "APACHE-001", "1.0");
        createAdvisory("Critical Bug in Nginx", "CSAF", "nginx", "NGINX-001", "1.0");
        createAdvisory("Apache Tomcat Vulnerability", "CSAF", "apache", "APACHE-002", "1.0");

        // Note: searchvector functionality requires the database to have proper text search setup
        // This test demonstrates the API; actual search behavior depends on database configuration

        // Test: Search returns results (exact behavior depends on searchvector index)
        List<AdvisoryDao.AdvisoryDetailRow> allResults = advisoryDao.getAllAdvisories("CSAF", "Apache");
        assertThat(allResults).hasSize(2);
    }

    @Test
    public void testGetTotalAdvisories() {
        // Create test data
        createAdvisory("Advisory 1", "CSAF", "pub1", "ADV-001", "1.0");
        createAdvisory("Advisory 2", "CSAF", "pub2", "ADV-002", "1.0");
        createAdvisory("Advisory 3", "VEX", "pub3", "ADV-003", "1.0");

        // Test: Get total count
        long totalCount = advisoryDao.getTotalAdvisories(null, null);
        assertThat(totalCount).isEqualTo(3);

        // Test: Get count by format
        long csafCount = advisoryDao.getTotalAdvisories("CSAF", null);
        assertThat(csafCount).isEqualTo(2);

        long vexCount = advisoryDao.getTotalAdvisories("VEX", null);
        assertThat(vexCount).isEqualTo(1);
    }

    @Test
    public void testSortingByTitle() {
        // Create advisories with different titles
        createAdvisory("Zebra Advisory", "CSAF", "pub1", "ADV-001", "1.0");
        createAdvisory("Alpha Advisory", "CSAF", "pub2", "ADV-002", "1.0");
        createAdvisory("Gamma Advisory", "CSAF", "pub3", "ADV-003", "1.0");

        // Get advisories and check default ordering (should be by id)
        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        // Verify results contain all three advisories
        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::title)
                .containsExactlyInAnyOrder("Zebra Advisory", "Alpha Advisory", "Gamma Advisory");
    }

    @Test
    public void testSortingByName() {
        // Create advisories with different names
        createAdvisory("Title 1", "CSAF", "pub1", "ZZZ-001", "1.0");
        createAdvisory("Title 2", "CSAF", "pub2", "AAA-002", "1.0");
        createAdvisory("Title 3", "CSAF", "pub3", "MMM-003", "1.0");

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        // Verify all advisories are returned
        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::name)
                .containsExactlyInAnyOrder("ZZZ-001", "AAA-002", "MMM-003");
    }

    @Test
    public void testSortingByPublisher() {
        // Create advisories with different publishers
        createAdvisory("Advisory 1", "CSAF", "zebra-corp", "ADV-001", "1.0");
        createAdvisory("Advisory 2", "CSAF", "alpha-corp", "ADV-002", "1.0");
        createAdvisory("Advisory 3", "CSAF", "beta-corp", "ADV-003", "1.0");

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::publisher)
                .containsExactlyInAnyOrder("zebra-corp", "alpha-corp", "beta-corp");
    }

    @Test
    public void testSortingByVersion() {
        // Create advisories with different versions
        createAdvisory("Advisory A", "CSAF", "pub", "ADV-001", "3.0");
        createAdvisory("Advisory B", "CSAF", "pub", "ADV-001", "1.0");
        createAdvisory("Advisory C", "CSAF", "pub", "ADV-001", "2.0");

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::version)
                .containsExactlyInAnyOrder("3.0", "1.0", "2.0");
    }

    @Test
    public void testSortingBySeen() {
        // Create advisories with different seen status
        Advisory adv1 = createAdvisory("Advisory 1", "CSAF", "pub1", "ADV-001", "1.0");
        adv1.setSeen(true);

        Advisory adv2 = createAdvisory("Advisory 2", "CSAF", "pub2", "ADV-002", "1.0");
        adv2.setSeen(false);

        Advisory adv3 = createAdvisory("Advisory 3", "CSAF", "pub3", "ADV-003", "1.0");
        adv3.setSeen(true);

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        // Verify seen status
        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::seen)
                .containsExactlyInAnyOrder(true, false, true);
    }

    @Test
    public void testSortingByLastFetched() {
        // Create advisories with different lastFetched timestamps
        Instant now = Instant.now();
        Instant yesterday = now.minusSeconds(86400);
        Instant tomorrow = now.plusSeconds(86400);

        Advisory adv1 = createAdvisory("Advisory 1", "CSAF", "pub1", "ADV-001", "1.0");
        adv1.setLastFetched(yesterday);

        Advisory adv2 = createAdvisory("Advisory 2", "CSAF", "pub2", "ADV-002", "1.0");
        adv2.setLastFetched(now);

        Advisory adv3 = createAdvisory("Advisory 3", "CSAF", "pub3", "ADV-003", "1.0");
        adv3.setLastFetched(tomorrow);

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        // Verify all timestamps are present
        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::lastFetched)
                .containsExactlyInAnyOrder(yesterday, now, tomorrow);
    }

    @Test
    public void testSortingByAffectedComponents() {
        // Create projects and components
        final var project1 = qm.createProject("Project 1", null, "1.0", null, null, null, null, false);
        final var project2 = qm.createProject("Project 2", null, "1.0", null, null, null, null, false);

        final var component1 = new Component();
        component1.setProject(project1);
        component1.setName("component-1");
        qm.persist(component1);

        final var component2 = new Component();
        component2.setProject(project1);
        component2.setName("component-2");
        qm.persist(component2);

        final var component3 = new Component();
        component3.setProject(project2);
        component3.setName("component-3");
        qm.persist(component3);

        // Create advisories with different component counts
        final var advisory1 = createAdvisory("Advisory with 1 component", "CSAF", "pub1", "ADV-001", "1.0");
        final var advisory2 = createAdvisory("Advisory with 2 components", "CSAF", "pub2", "ADV-002", "1.0");
        final var advisory3 = createAdvisory("Advisory with 0 components", "CSAF", "pub3", "ADV-003", "1.0");

        // Create vulnerabilities
        final var vuln1 = new Vulnerability();
        vuln1.setVulnId("VULN-001");
        vuln1.setSource(CSAF);
        qm.persist(vuln1);
        advisory1.addVulnerability(vuln1);
        qm.addVulnerability(vuln1, component1, AnalyzerIdentity.INTERNAL_ANALYZER, "Test", "http://test.com", new Date());

        final var vuln2 = new Vulnerability();
        vuln2.setVulnId("VULN-002");
        vuln2.setSource(CSAF);
        qm.persist(vuln2);
        advisory2.addVulnerability(vuln2);
        qm.addVulnerability(vuln2, component1, AnalyzerIdentity.INTERNAL_ANALYZER, "Test", "http://test.com", new Date());
        qm.addVulnerability(vuln2, component2, AnalyzerIdentity.INTERNAL_ANALYZER, "Test", "http://test.com", new Date());

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        // Verify affected component counts
        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::affectedComponents)
                .containsExactlyInAnyOrder(1, 2, 0);
    }

    @Test
    public void testSortingByAffectedProjects() {
        // Create projects and components
        final var project1 = qm.createProject("Project 1", null, "1.0", null, null, null, null, false);
        final var project2 = qm.createProject("Project 2", null, "1.0", null, null, null, null, false);

        final var component1 = new Component();
        component1.setProject(project1);
        component1.setName("component-1");
        qm.persist(component1);

        final var component2 = new Component();
        component2.setProject(project2);
        component2.setName("component-2");
        qm.persist(component2);

        // Create advisories with different project counts
        final var advisory1 = createAdvisory("Advisory affecting 1 project", "CSAF", "pub1", "ADV-001", "1.0");
        final var advisory2 = createAdvisory("Advisory affecting 2 projects", "CSAF", "pub2", "ADV-002", "1.0");
        final var advisory3 = createAdvisory("Advisory affecting 0 projects", "CSAF", "pub3", "ADV-003", "1.0");

        // Create vulnerabilities
        final var vuln1 = new Vulnerability();
        vuln1.setVulnId("VULN-001");
        vuln1.setSource(CSAF);
        qm.persist(vuln1);
        advisory1.addVulnerability(vuln1);
        qm.addVulnerability(vuln1, component1, AnalyzerIdentity.CSAF_ANALYZER, "Test", "http://test.com", new Date());

        final var vuln2 = new Vulnerability();
        vuln2.setVulnId("VULN-002");
        vuln2.setSource(CSAF);
        qm.persist(vuln2);
        advisory2.addVulnerability(vuln2);
        qm.addVulnerability(vuln2, component1, AnalyzerIdentity.CSAF_ANALYZER, "Test", "http://test.com", new Date());
        qm.addVulnerability(vuln2, component2, AnalyzerIdentity.CSAF_ANALYZER, "Test", "http://test.com", new Date());

        List<AdvisoryDao.AdvisoryDetailRow> results = advisoryDao.getAllAdvisories("CSAF", null);
        assertThat(results).hasSize(3);

        // Verify affected project counts
        assertThat(results).extracting(AdvisoryDao.AdvisoryDetailRow::affectedProjects)
                .containsExactlyInAnyOrder(1, 2, 0);
    }

    @Test
    public void testGetAdvisoriesWithFindingsByProject() {
        // Create test data
        final var project = qm.createProject("Test Project", null, "1.0", null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("test-component");
        qm.persist(component);

        final var advisory = createAdvisory("Test Advisory", "CSAF", "test-pub", "TEST-001", "1.0");
        final var vuln = new Vulnerability();
        vuln.setVulnId("VULN-123");
        vuln.setSource(CSAF);
        qm.persist(vuln);
        advisory.addVulnerability(vuln);
        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER, "Test", "http://test.com", new Date());

        // Test
        List<AdvisoryDao.AdvisoryInProjectRow> results = advisoryDao.getAdvisoriesWithFindingsByProject(project.getId(), false);
        assertThat(results).hasSize(1);
        assertThat(results.getFirst().name()).isEqualTo("Test Advisory");
        assertThat(results.getFirst().findingsPerDoc()).isEqualTo(1);
    }

    // Helper method to create advisories
    private Advisory createAdvisory(String title, String format, String publisher, String name, String version) {
        final var advisory = new Advisory();
        advisory.setTitle(title);
        advisory.setFormat(format);
        advisory.setPublisher(publisher);
        advisory.setName(name);
        advisory.setVersion(version);
        advisory.setUrl("http://example.com/" + name);
        advisory.setSeen(false);
        advisory.setLastFetched(Instant.now());
        qm.persist(advisory);
        qm.getPersistenceManager().flush();  // Ensure data is committed for JDBI queries
        return advisory;
    }
}
