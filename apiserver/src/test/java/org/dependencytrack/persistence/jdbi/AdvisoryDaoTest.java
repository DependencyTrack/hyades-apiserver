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
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.AdvisoryDao.ListAdvisoriesRow;
import org.dependencytrack.persistence.jdbi.query.ListAdvisoriesQuery;
import org.jdbi.v3.core.Handle;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;

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
    public void testList() {
        // Create test data
        createAdvisory("Advisory Alpha", "CSAF", "publisher1", "ADV-001", "1.0");
        createAdvisory("Advisory Beta", "CSAF", "publisher2", "ADV-002", "2.0");
        createAdvisory("Advisory Gamma", "OTHER", "publisher3", "ADV-003", "1.5");

        // Test: Get all advisories without a filter
        Page<ListAdvisoriesRow> results = advisoryDao.list(new ListAdvisoriesQuery());
        assertThat(results.items()).hasSize(3);

        // Test: Filter by format
        Page<ListAdvisoriesRow> csafResults = advisoryDao.list(new ListAdvisoriesQuery().withFormat("CSAF"));
        assertThat(csafResults.items()).hasSize(2);
        assertThat(csafResults.items()).extracting(ListAdvisoriesRow::title)
                .containsExactlyInAnyOrder("Advisory Alpha", "Advisory Beta");

        Page<ListAdvisoriesRow> vexResults = advisoryDao.list(new ListAdvisoriesQuery().withFormat("OTHER"));
        assertThat(vexResults.items()).hasSize(1);
        assertThat(vexResults.items().getFirst().title()).isEqualTo("Advisory Gamma");
    }

    @Test
    public void testListWithAffectedCounts() {
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
        Page<ListAdvisoriesRow> results = advisoryDao.list(new ListAdvisoriesQuery().withFormat("CSAF"));
        assertThat(results.items()).hasSize(1);

        ListAdvisoriesRow result = results.items().getFirst();
        assertThat(result.title()).isEqualTo("Test Advisory");
        assertThat(result.affectedComponentCount()).isEqualTo(3);
        assertThat(result.affectedProjectCount()).isEqualTo(2);
    }

    @Test
    public void testListSearchText() {
        // Create test data with searchable content
        createAdvisory("Security Alert for Apache", "CSAF", "apache", "APACHE-001", "1.0");
        createAdvisory("Critical Bug in Nginx", "CSAF", "nginx", "NGINX-001", "1.0");
        createAdvisory("Apache Tomcat Vulnerability", "CSAF", "apache", "APACHE-002", "1.0");

        // Note: searchvector functionality requires the database to have proper text search setup
        // This test demonstrates the API; actual search behavior depends on database configuration

        // Test: Search returns results (exact behavior depends on searchvector index)
        Page<ListAdvisoriesRow> allResults = advisoryDao.list(
                new ListAdvisoriesQuery()
                        .withFormat("CSAF")
                        .withSearchText("Apache"));
        assertThat(allResults.items()).hasSize(2);
    }

    @Test
    public void testListSearchTextCaseInsensitive() {
        // Create test data with searchable content
        createAdvisory("Case Test Apache", "CSAF", "apache", "CASE-APACHE-001", "1.0");
        createAdvisory("Another Apache Issue", "CSAF", "apache", "CASE-APACHE-002", "1.0");
        createAdvisory("Unrelated Issue", "CSAF", "other", "CASE-OTHER-001", "1.0");

        // Search with lowercase
        Page<ListAdvisoriesRow> lowerResults = advisoryDao.list(
                new ListAdvisoriesQuery()
                        .withFormat("CSAF")
                        .withSearchText("apache"));
        // Search with uppercase
        Page<ListAdvisoriesRow> upperResults = advisoryDao.list(
                new ListAdvisoriesQuery()
                        .withFormat("CSAF")
                        .withSearchText("APACHE"));
        // Search with mixed case
        Page<ListAdvisoriesRow> mixedResults = advisoryDao.list(
                new ListAdvisoriesQuery()
                        .withFormat("CSAF")
                        .withSearchText("ApAcHe"));

        assertThat(lowerResults.items()).hasSize(2);
        assertThat(upperResults.items()).hasSize(2);
        assertThat(mixedResults.items()).hasSize(2);

        // Verify that titles returned are the same across casings
        assertThat(lowerResults.items()).extracting(ListAdvisoriesRow::title).containsExactlyInAnyOrder("Case Test Apache", "Another Apache Issue");
        assertThat(upperResults.items()).extracting(ListAdvisoriesRow::title).containsExactlyInAnyOrder("Case Test Apache", "Another Apache Issue");
        assertThat(mixedResults.items()).extracting(ListAdvisoriesRow::title).containsExactlyInAnyOrder("Case Test Apache", "Another Apache Issue");
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
        advisory.setLastFetched(Instant.now());
        qm.persist(advisory);
        qm.getPersistenceManager().flush();  // Ensure data is committed for JDBI queries
        return advisory;
    }
}
