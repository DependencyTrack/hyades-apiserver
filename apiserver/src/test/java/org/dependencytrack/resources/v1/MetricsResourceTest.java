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
import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.util.DateUtil;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Date;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

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
    public void getPortfolioMetricsXDaysAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            dao.createPartitionForDaysAgo("PORTFOLIOMETRICS", 30);
            var metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(3);
            metrics.setFirstOccurrence(Date.from(Instant.now()));
            metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
            dao.createPortfolioMetrics(metrics);

            dao.createPartitionForDaysAgo("PORTFOLIOMETRICS", 20);
            metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(2);
            metrics.setFirstOccurrence(Date.from(Instant.now()));
            metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
            dao.createPortfolioMetrics(metrics);
        });

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/portfolio/25/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(1);
        assertThat(json.getJsonObject(0).getInt("vulnerabilities")).isEqualTo(2);
    }

    @Test
    public void getPortfolioMetricsSinceAclTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            dao.createMetricsPartitionsForDate("PORTFOLIOMETRICS", LocalDate.of(2025, 1, 1));
            var metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(3);
            metrics.setFirstOccurrence(Date.from(Instant.now()));
            metrics.setLastOccurrence(DateUtil.parseShortDate("20250101"));
            dao.createPortfolioMetrics(metrics);

            dao.createMetricsPartitionsForDate("PORTFOLIOMETRICS", LocalDate.of(2025, 2, 1));
            metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(2);
            metrics.setFirstOccurrence(Date.from(Instant.now()));
            metrics.setLastOccurrence(DateUtil.parseShortDate("20250201"));
            dao.createPortfolioMetrics(metrics);
        });

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/portfolio/since/20250201")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(1);
        assertThat(json.getJsonObject(0).getInt("vulnerabilities")).isEqualTo(2);
    }
}
