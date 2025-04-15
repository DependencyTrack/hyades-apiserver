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
import alpine.server.filters.AuthenticationFilter;
import alpine.server.filters.AuthorizationFilter;
import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.util.DateUtil;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.METRIC_DAYS_COMPONENT;
import static org.dependencytrack.model.ConfigPropertyConstants.METRIC_DAYS_PORTFOLIO;
import static org.dependencytrack.model.ConfigPropertyConstants.METRIC_DAYS_PROJECT;

public class MetricsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(MetricsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(AuthorizationFilter.class));

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
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        qm.createConfigProperty(
                METRIC_DAYS_PROJECT.getGroupName(),
                METRIC_DAYS_PROJECT.getPropertyName(),
                String.valueOf(35),
                METRIC_DAYS_PROJECT.getPropertyType(),
                METRIC_DAYS_PROJECT.getDescription()
        );

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + project.getUuid() + "/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        var metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(4);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(metrics);

        metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        metrics = new ProjectMetrics();
        metrics.setProject(project);
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.getJsonObject(0).getInt("vulnerabilities")).isEqualTo(3);
        assertThat(json.getJsonObject(1).getInt("vulnerabilities")).isEqualTo(2);
    }

    @Test
    public void getProjectMetricsXDays404Test() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/project/" + UUID.randomUUID() + "/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The project could not be found.");
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
        qm.createConfigProperty(
                METRIC_DAYS_COMPONENT.getGroupName(),
                METRIC_DAYS_COMPONENT.getPropertyName(),
                String.valueOf(25),
                METRIC_DAYS_COMPONENT.getPropertyType(),
                METRIC_DAYS_COMPONENT.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        var metrics = new DependencyMetrics();
        metrics.setProject(project);
        metrics.setComponent(component);
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        metrics = new DependencyMetrics();
        metrics.setProject(project);
        metrics.setComponent(component);
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + component.getUuid() + "/days")
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
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(1);
        assertThat(json.getJsonObject(0).getInt("vulnerabilities")).isEqualTo(2);
    }

    @Test
    public void getComponentMetricsXDays404Test() {
        enablePortfolioAccessControl();
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/component/" + UUID.randomUUID() + "/days")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The component could not be found.");
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
        qm.createConfigProperty(
                METRIC_DAYS_PORTFOLIO.getGroupName(),
                METRIC_DAYS_PORTFOLIO.getPropertyName(),
                String.valueOf(25),
                METRIC_DAYS_PORTFOLIO.getPropertyType(),
                METRIC_DAYS_PORTFOLIO.getDescription()
        );

        var metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(30))));
        qm.persist(metrics);

        metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofDays(20))));
        qm.persist(metrics);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_METRICS + "/portfolio/days")
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

        var metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(3);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(DateUtil.parseShortDate("20250101"));
        qm.persist(metrics);

        metrics = new PortfolioMetrics();
        metrics.setVulnerabilities(2);
        metrics.setFirstOccurrence(new Date());
        metrics.setLastOccurrence(DateUtil.parseShortDate("20250201"));
        qm.persist(metrics);

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