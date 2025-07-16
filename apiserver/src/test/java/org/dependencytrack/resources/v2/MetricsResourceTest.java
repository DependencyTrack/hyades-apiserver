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
package org.dependencytrack.resources.v2;

import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class MetricsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(new ResourceConfig());

    @Test
    public void getCurrentPortfolioMetricsEmptyTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        final Response response = jersey
                .target("/metrics/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "components": 0,
                          "critical": 0,
                          "findings_audited": 0,
                          "findings_total": 0,
                          "findings_unaudited": 0,
                          "high": 0,
                          "inherited_risk_score": 0.0,
                          "low": 0,
                          "medium": 0,
                          "observed_at": "${json-unit.any-number}",
                          "policy_violations_audited": 0,
                          "policy_violations_fail": 0,
                          "policy_violations_info": 0,
                          "policy_violations_license_audited": 0,
                          "policy_violations_license_total": 0,
                          "policy_violations_license_unaudited": 0,
                          "policy_violations_operational_audited": 0,
                          "policy_violations_operational_total": 0,
                          "policy_violations_operational_unaudited": 0,
                          "policy_violations_security_audited": 0,
                          "policy_violations_security_total": 0,
                          "policy_violations_security_unaudited": 0,
                          "policy_violations_total": 0,
                          "policy_violations_unaudited": 0,
                          "policy_violations_warn": 0,
                          "projects": 0,
                          "suppressed": 0,
                          "unassigned": 0,
                          "vulnerabilities": 0,
                          "vulnerable_components": 0,
                          "vulnerable_projects": 0
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
                .target("/metrics/portfolio/current")
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
    public void getVulnerabilityMetricsPaginated() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        for (int i = 1; i < 4; i++) {
            var metrics = new VulnerabilityMetrics();
            metrics.setYear(2025);
            metrics.setMonth(i);
            metrics.setCount(i);
            metrics.setMeasuredAt(Date.from(Instant.now()));
            qm.persist(metrics);
        }

        Response response = jersey.target("/metrics/vulnerabilities")
                .queryParam("limit", 2)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        final JsonObject responseJson = parseJsonObject(response);
        assertThatJson(responseJson.toString()).isEqualTo(/* language=JSON */ """
                {
                  "metrics" :
                  [
                      {
                        "observed_at" : "${json-unit.any-number}",
                        "year" : 2025,
                        "month" : 1,
                        "count" : 1
                      },
                      {
                        "observed_at" : "${json-unit.any-number}",
                        "year" : 2025,
                        "month" : 2,
                        "count" : 2
                      }
                  ],
                  "_pagination" : {
                    "links" : {
                      "self" : "${json-unit.any-string}",
                      "next": "${json-unit.any-string}"
                    }
                  }
                }
                """);

        final var nextPageUri = URI.create(
                responseJson
                        .getJsonObject("_pagination")
                        .getJsonObject("links")
                        .getString("next"));

        response = jersey.target(nextPageUri)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "metrics" :
                  [
                      {
                        "observed_at" : "${json-unit.any-number}",
                        "year" : 2025,
                        "month" : 3,
                        "count" : 3
                      }
                  ],
                  "_pagination": {
                    "links": {
                      "self": "${json-unit.any-string}"
                    }
                  }
                }
                """);
    }
}