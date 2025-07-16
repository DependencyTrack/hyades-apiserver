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
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.core.Response;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.hamcrest.Matchers.closeTo;

public class MetricsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(MetricsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getProjectCurrentMetricsAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getProjectMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/since/20250101")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getProjectMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/days/666")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void refreshProjectMetricsAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/refresh")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentCurrentMetricsAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/since/20250101")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getComponentMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/days/666")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void refreshComponentMetricsAclTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/refresh")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getCurrentPortfolioMetricsEmptyTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": 0,
                          "critical": 0,
                          "findingsAudited": 0,
                          "findingsTotal": 0,
                          "findingsUnaudited": 0,
                          "firstOccurrence": "${json-unit.any-number}",
                          "high": 0,
                          "inheritedRiskScore": 0.0,
                          "lastOccurrence": "${json-unit.any-number}",
                          "low": 0,
                          "medium": 0,
                          "policyViolationsAudited": 0,
                          "policyViolationsFail": 0,
                          "policyViolationsInfo": 0,
                          "policyViolationsLicenseAudited": 0,
                          "policyViolationsLicenseTotal": 0,
                          "policyViolationsLicenseUnaudited": 0,
                          "policyViolationsOperationalAudited": 0,
                          "policyViolationsOperationalTotal": 0,
                          "policyViolationsOperationalUnaudited": 0,
                          "policyViolationsSecurityAudited": 0,
                          "policyViolationsSecurityTotal": 0,
                          "policyViolationsSecurityUnaudited": 0,
                          "policyViolationsTotal": 0,
                          "policyViolationsUnaudited": 0,
                          "policyViolationsWarn": 0,
                          "projects": 0,
                          "suppressed": 0,
                          "unassigned": 0,
                          "vulnerabilities": 0,
                          "vulnerableComponents": 0,
                          "vulnerableProjects": 0
                        }
                        """);
    }

    @Test
    public void getCurrentPortfolioMetricsAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final var today = LocalDate.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(2);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(today.minusDays(1).atTime(1, 1).atZone(ZoneId.systemDefault()).toInstant()));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(1);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(today.atTime(1, 1).atZone(ZoneId.systemDefault()).toInstant()));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(today.atTime(2, 2).atZone(ZoneId.systemDefault()).toInstant()));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of inaccessible projects must not be considered.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setComponents(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(today.atTime(3, 3).atZone(ZoneId.systemDefault()).toInstant()));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_EXTRA_FIELDS)
                .isEqualTo(/* language=JSON */ """
                        {
                          "projects": 2,
                          "components": 3
                        }
                        """);
    }

    @Test
    public void getPortfolioMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final var today = LocalDate.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(1);
                accessibleProjectAMetrics.setCritical(1);
                accessibleProjectAMetrics.setFindingsAudited(1);
                accessibleProjectAMetrics.setFindingsTotal(1);
                accessibleProjectAMetrics.setFindingsUnaudited(1);
                accessibleProjectAMetrics.setHigh(1);
                accessibleProjectAMetrics.setInheritedRiskScore(1.1);
                accessibleProjectAMetrics.setLow(1);
                accessibleProjectAMetrics.setMedium(1);
                accessibleProjectAMetrics.setPolicyViolationsAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsFail(1);
                accessibleProjectAMetrics.setPolicyViolationsInfo(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsWarn(1);
                accessibleProjectAMetrics.setSuppressed(1);
                accessibleProjectAMetrics.setUnassigned(1);
                accessibleProjectAMetrics.setVulnerabilities(1);
                accessibleProjectAMetrics.setVulnerableComponents(1);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(today.minusDays(1).atTime(1, 1).atZone(ZoneId.systemDefault()).toInstant()));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(2);
                accessibleProjectBMetrics.setCritical(2);
                accessibleProjectBMetrics.setFindingsAudited(2);
                accessibleProjectBMetrics.setFindingsTotal(2);
                accessibleProjectBMetrics.setFindingsUnaudited(2);
                accessibleProjectBMetrics.setHigh(2);
                accessibleProjectBMetrics.setInheritedRiskScore(2.2);
                accessibleProjectBMetrics.setLow(2);
                accessibleProjectBMetrics.setMedium(2);
                accessibleProjectBMetrics.setPolicyViolationsAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsFail(2);
                accessibleProjectBMetrics.setPolicyViolationsInfo(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsWarn(2);
                accessibleProjectBMetrics.setSuppressed(2);
                accessibleProjectBMetrics.setUnassigned(2);
                accessibleProjectBMetrics.setVulnerabilities(2);
                accessibleProjectBMetrics.setVulnerableComponents(2);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(today.atTime(2, 2).atZone(ZoneId.systemDefault()).toInstant()));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(today.atTime(2, 2).atZone(ZoneId.systemDefault()).toInstant()));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of inaccessible projects must not be considered.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setVulnerabilities(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(today.atTime(3, 3).atZone(ZoneId.systemDefault()).toInstant()));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/3/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("inheritedRiskScoreDay2", closeTo(BigDecimal.valueOf(1.1), BigDecimal.valueOf(0.01)))
                .withMatcher("inheritedRiskScoreDay3", closeTo(BigDecimal.valueOf(3.3), BigDecimal.valueOf(0.01)))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "components": 0,
                            "critical": 0,
                            "findingsAudited": 0,
                            "findingsTotal": 0,
                            "findingsUnaudited": 0,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 0,
                            "inheritedRiskScore": 0.0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 0,
                            "medium": 0,
                            "policyViolationsAudited": 0,
                            "policyViolationsFail": 0,
                            "policyViolationsInfo": 0,
                            "policyViolationsLicenseAudited": 0,
                            "policyViolationsLicenseTotal": 0,
                            "policyViolationsLicenseUnaudited": 0,
                            "policyViolationsOperationalAudited": 0,
                            "policyViolationsOperationalTotal": 0,
                            "policyViolationsOperationalUnaudited": 0,
                            "policyViolationsSecurityAudited": 0,
                            "policyViolationsSecurityTotal": 0,
                            "policyViolationsSecurityUnaudited": 0,
                            "policyViolationsTotal": 0,
                            "policyViolationsUnaudited": 0,
                            "policyViolationsWarn": 0,
                            "projects": 0,
                            "suppressed": 0,
                            "unassigned": 0,
                            "vulnerabilities": 0,
                            "vulnerableComponents": 0,
                            "vulnerableProjects": 0
                          },
                          {
                            "components": 1,
                            "critical": 1,
                            "findingsAudited": 1,
                            "findingsTotal": 1,
                            "findingsUnaudited": 1,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 1,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay2}",
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 1,
                            "medium": 1,
                            "policyViolationsAudited": 1,
                            "policyViolationsFail": 1,
                            "policyViolationsInfo": 1,
                            "policyViolationsLicenseAudited": 1,
                            "policyViolationsLicenseTotal": 1,
                            "policyViolationsLicenseUnaudited": 1,
                            "policyViolationsOperationalAudited": 1,
                            "policyViolationsOperationalTotal": 1,
                            "policyViolationsOperationalUnaudited": 1,
                            "policyViolationsSecurityAudited": 1,
                            "policyViolationsSecurityTotal": 1,
                            "policyViolationsSecurityUnaudited": 1,
                            "policyViolationsTotal": 1,
                            "policyViolationsUnaudited": 1,
                            "policyViolationsWarn": 1,
                            "projects": 1,
                            "suppressed": 1,
                            "unassigned": 1,
                            "vulnerabilities": 1,
                            "vulnerableComponents": 1,
                            "vulnerableProjects": 1
                          },
                          {
                            "components": 3,
                            "critical": 3,
                            "findingsAudited": 3,
                            "findingsTotal": 3,
                            "findingsUnaudited": 3,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 3,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay3}",
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 3,
                            "medium": 3,
                            "policyViolationsAudited": 3,
                            "policyViolationsFail": 3,
                            "policyViolationsInfo": 3,
                            "policyViolationsLicenseAudited": 3,
                            "policyViolationsLicenseTotal": 3,
                            "policyViolationsLicenseUnaudited": 3,
                            "policyViolationsOperationalAudited": 3,
                            "policyViolationsOperationalTotal": 3,
                            "policyViolationsOperationalUnaudited": 3,
                            "policyViolationsSecurityAudited": 3,
                            "policyViolationsSecurityTotal": 3,
                            "policyViolationsSecurityUnaudited": 3,
                            "policyViolationsTotal": 3,
                            "policyViolationsUnaudited": 3,
                            "policyViolationsWarn": 3,
                            "projects": 2,
                            "suppressed": 3,
                            "unassigned": 3,
                            "vulnerabilities": 3,
                            "vulnerableComponents": 3,
                            "vulnerableProjects": 2
                          }
                        ]
                        """);
    }

    @Test
    public void getPortfolioMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var accessibleProjectA = new Project();
        accessibleProjectA.setName("acme-app-a");
        accessibleProjectA.addAccessTeam(super.team);
        qm.persist(accessibleProjectA);

        final var accessibleProjectB = new Project();
        accessibleProjectB.setName("acme-app-b");
        accessibleProjectB.addAccessTeam(super.team);
        qm.persist(accessibleProjectB);

        final var inactiveAccessibleProject = new Project();
        inactiveAccessibleProject.setName("acme-app-inactive");
        inactiveAccessibleProject.setInactiveSince(new Date());
        inactiveAccessibleProject.addAccessTeam(super.team);
        qm.persist(inactiveAccessibleProject);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final var today = LocalDate.now();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);

            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today);
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(1));
            dao.createMetricsPartitionsForDate("PROJECTMETRICS", today.minusDays(2));

            {
                // Create metrics for "yesterday".

                var accessibleProjectAMetrics = new ProjectMetrics();
                accessibleProjectAMetrics.setProjectId(accessibleProjectA.getId());
                accessibleProjectAMetrics.setComponents(1);
                accessibleProjectAMetrics.setCritical(1);
                accessibleProjectAMetrics.setFindingsAudited(1);
                accessibleProjectAMetrics.setFindingsTotal(1);
                accessibleProjectAMetrics.setFindingsUnaudited(1);
                accessibleProjectAMetrics.setHigh(1);
                accessibleProjectAMetrics.setInheritedRiskScore(1.1);
                accessibleProjectAMetrics.setLow(1);
                accessibleProjectAMetrics.setMedium(1);
                accessibleProjectAMetrics.setPolicyViolationsAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsFail(1);
                accessibleProjectAMetrics.setPolicyViolationsInfo(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsLicenseUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsOperationalUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityAudited(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsSecurityUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsTotal(1);
                accessibleProjectAMetrics.setPolicyViolationsUnaudited(1);
                accessibleProjectAMetrics.setPolicyViolationsWarn(1);
                accessibleProjectAMetrics.setSuppressed(1);
                accessibleProjectAMetrics.setUnassigned(1);
                accessibleProjectAMetrics.setVulnerabilities(1);
                accessibleProjectAMetrics.setVulnerableComponents(1);
                accessibleProjectAMetrics.setFirstOccurrence(Date.from(today.minusDays(1).atTime(1, 1).atZone(ZoneId.systemDefault()).toInstant()));
                accessibleProjectAMetrics.setLastOccurrence(accessibleProjectAMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectAMetrics);
            }

            {
                // Create metrics for "today".

                // Do not create metrics for accessibleProjectA.
                // Its metrics from "yesterday" are supposed to carry over to "today".

                var accessibleProjectBMetrics = new ProjectMetrics();
                accessibleProjectBMetrics.setProjectId(accessibleProjectB.getId());
                accessibleProjectBMetrics.setComponents(2);
                accessibleProjectBMetrics.setCritical(2);
                accessibleProjectBMetrics.setFindingsAudited(2);
                accessibleProjectBMetrics.setFindingsTotal(2);
                accessibleProjectBMetrics.setFindingsUnaudited(2);
                accessibleProjectBMetrics.setHigh(2);
                accessibleProjectBMetrics.setInheritedRiskScore(2.2);
                accessibleProjectBMetrics.setLow(2);
                accessibleProjectBMetrics.setMedium(2);
                accessibleProjectBMetrics.setPolicyViolationsAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsFail(2);
                accessibleProjectBMetrics.setPolicyViolationsInfo(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsLicenseUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsOperationalUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityAudited(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsSecurityUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsTotal(2);
                accessibleProjectBMetrics.setPolicyViolationsUnaudited(2);
                accessibleProjectBMetrics.setPolicyViolationsWarn(2);
                accessibleProjectBMetrics.setSuppressed(2);
                accessibleProjectBMetrics.setUnassigned(2);
                accessibleProjectBMetrics.setVulnerabilities(2);
                accessibleProjectBMetrics.setVulnerableComponents(2);
                accessibleProjectBMetrics.setFirstOccurrence(Date.from(today.atTime(2, 2).atZone(ZoneId.systemDefault()).toInstant()));
                accessibleProjectBMetrics.setLastOccurrence(accessibleProjectBMetrics.getFirstOccurrence());
                dao.createProjectMetrics(accessibleProjectBMetrics);

                // Metrics of inactive projects must not be considered.
                var inactiveAccessibleProjectMetrics = new ProjectMetrics();
                inactiveAccessibleProjectMetrics.setProjectId(inactiveAccessibleProject.getId());
                inactiveAccessibleProjectMetrics.setComponents(111);
                inactiveAccessibleProjectMetrics.setFirstOccurrence(Date.from(today.atTime(2, 2).atZone(ZoneId.systemDefault()).toInstant()));
                inactiveAccessibleProjectMetrics.setLastOccurrence(inactiveAccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inactiveAccessibleProjectMetrics);

                // Metrics of inaccessible projects must not be considered.
                var inaccessibleProjectMetrics = new ProjectMetrics();
                inaccessibleProjectMetrics.setProjectId(inaccessibleProject.getId());
                inaccessibleProjectMetrics.setVulnerabilities(666);
                inaccessibleProjectMetrics.setFirstOccurrence(Date.from(today.atTime(3, 3).atZone(ZoneId.systemDefault()).toInstant()));
                inaccessibleProjectMetrics.setLastOccurrence(inaccessibleProjectMetrics.getFirstOccurrence());
                dao.createProjectMetrics(inaccessibleProjectMetrics);
            }
        });

        final Response response = jersey
                .target(V1_METRICS + "/portfolio/since/" + today.minusDays(2).format(DateTimeFormatter.ofPattern("yyyyMMdd")))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("inheritedRiskScoreDay2", closeTo(BigDecimal.valueOf(1.1), BigDecimal.valueOf(0.01)))
                .withMatcher("inheritedRiskScoreDay3", closeTo(BigDecimal.valueOf(3.3), BigDecimal.valueOf(0.01)))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "components": 0,
                            "critical": 0,
                            "findingsAudited": 0,
                            "findingsTotal": 0,
                            "findingsUnaudited": 0,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 0,
                            "inheritedRiskScore": 0.0,
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 0,
                            "medium": 0,
                            "policyViolationsAudited": 0,
                            "policyViolationsFail": 0,
                            "policyViolationsInfo": 0,
                            "policyViolationsLicenseAudited": 0,
                            "policyViolationsLicenseTotal": 0,
                            "policyViolationsLicenseUnaudited": 0,
                            "policyViolationsOperationalAudited": 0,
                            "policyViolationsOperationalTotal": 0,
                            "policyViolationsOperationalUnaudited": 0,
                            "policyViolationsSecurityAudited": 0,
                            "policyViolationsSecurityTotal": 0,
                            "policyViolationsSecurityUnaudited": 0,
                            "policyViolationsTotal": 0,
                            "policyViolationsUnaudited": 0,
                            "policyViolationsWarn": 0,
                            "projects": 0,
                            "suppressed": 0,
                            "unassigned": 0,
                            "vulnerabilities": 0,
                            "vulnerableComponents": 0,
                            "vulnerableProjects": 0
                          },
                          {
                            "components": 1,
                            "critical": 1,
                            "findingsAudited": 1,
                            "findingsTotal": 1,
                            "findingsUnaudited": 1,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 1,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay2}",
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 1,
                            "medium": 1,
                            "policyViolationsAudited": 1,
                            "policyViolationsFail": 1,
                            "policyViolationsInfo": 1,
                            "policyViolationsLicenseAudited": 1,
                            "policyViolationsLicenseTotal": 1,
                            "policyViolationsLicenseUnaudited": 1,
                            "policyViolationsOperationalAudited": 1,
                            "policyViolationsOperationalTotal": 1,
                            "policyViolationsOperationalUnaudited": 1,
                            "policyViolationsSecurityAudited": 1,
                            "policyViolationsSecurityTotal": 1,
                            "policyViolationsSecurityUnaudited": 1,
                            "policyViolationsTotal": 1,
                            "policyViolationsUnaudited": 1,
                            "policyViolationsWarn": 1,
                            "projects": 1,
                            "suppressed": 1,
                            "unassigned": 1,
                            "vulnerabilities": 1,
                            "vulnerableComponents": 1,
                            "vulnerableProjects": 1
                          },
                          {
                            "components": 3,
                            "critical": 3,
                            "findingsAudited": 3,
                            "findingsTotal": 3,
                            "findingsUnaudited": 3,
                            "firstOccurrence": "${json-unit.any-number}",
                            "high": 3,
                            "inheritedRiskScore": "${json-unit.matches:inheritedRiskScoreDay3}",
                            "lastOccurrence": "${json-unit.any-number}",
                            "low": 3,
                            "medium": 3,
                            "policyViolationsAudited": 3,
                            "policyViolationsFail": 3,
                            "policyViolationsInfo": 3,
                            "policyViolationsLicenseAudited": 3,
                            "policyViolationsLicenseTotal": 3,
                            "policyViolationsLicenseUnaudited": 3,
                            "policyViolationsOperationalAudited": 3,
                            "policyViolationsOperationalTotal": 3,
                            "policyViolationsOperationalUnaudited": 3,
                            "policyViolationsSecurityAudited": 3,
                            "policyViolationsSecurityTotal": 3,
                            "policyViolationsSecurityUnaudited": 3,
                            "policyViolationsTotal": 3,
                            "policyViolationsUnaudited": 3,
                            "policyViolationsWarn": 3,
                            "projects": 2,
                            "suppressed": 3,
                            "unassigned": 3,
                            "vulnerabilities": 3,
                            "vulnerableComponents": 3,
                            "vulnerableProjects": 2
                          }
                        ]
                        """);
    }
}
