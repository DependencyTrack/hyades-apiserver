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
import org.datanucleus.store.types.wrappers.Date;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class MetricsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(MetricsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(AuthorizationFilter.class));

    @Test
    public void getPortfolioMetricsSinceTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final var projectA = new Project();
        projectA.setName("acme-app-a");
        projectA.addAccessTeam(super.team);
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var metricsA = new ProjectMetrics();
        metricsA.setProject(projectA);
        metricsA.setCritical(1);
        metricsA.setFirstOccurrence(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)));
        metricsA.setLastOccurrence(metricsA.getFirstOccurrence());
        qm.persist(metricsA);

        final var metricsA2 = new ProjectMetrics();
        metricsA2.setProject(projectA);
        metricsA2.setCritical(666);
        metricsA2.setFirstOccurrence(Date.from(Instant.now().minus(1, ChronoUnit.DAYS).minus(45, ChronoUnit.MINUTES)));
        metricsA2.setLastOccurrence(metricsA2.getFirstOccurrence());
        qm.persist(metricsA2);

        final Response response = jersey.target(V1_METRICS + "/portfolio/since/20250306/v2")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                [
                  {
                    "day": "${json-unit.any-number}",
                    "day_str": "${json-unit.any-string}",
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unassigned": 0
                  },
                  {
                    "day": "${json-unit.any-number}",
                    "day_str": "${json-unit.any-string}",
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unassigned": 0
                  },
                  {
                    "day": "${json-unit.any-number}",
                    "day_str": "${json-unit.any-string}",
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unassigned": 0
                  },
                  {
                    "day": "${json-unit.any-number}",
                    "day_str": "${json-unit.any-string}",
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unassigned": 0
                  },
                  {
                    "day": "${json-unit.any-number}",
                    "day_str": "${json-unit.any-string}",
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unassigned": 0
                  }
                ]
                """);
    }

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

}