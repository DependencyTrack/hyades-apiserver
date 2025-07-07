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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class MetricsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(MetricsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(MultiPartFeature.class));

    @Test
    public void getPortfolioCurrentMetricsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            var metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(3);
            metrics.setFirstOccurrence(Date.from(Instant.now()));
            metrics.setLastOccurrence(Date.from(Instant.now().plusSeconds(10)));
            dao.createPortfolioMetrics(metrics);

            dao.createPartitionForDaysAgo("PORTFOLIOMETRICS", 20);
            metrics = new PortfolioMetrics();
            metrics.setVulnerabilities(2);
            metrics.setFirstOccurrence(Date.from(Instant.now()));
            metrics.setLastOccurrence(Date.from(Instant.now().plusSeconds(20)));
            dao.createPortfolioMetrics(metrics);
        });

        final Supplier<Response> responseSupplier = () -> jersey
                .target("metrics/portfolio/current")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        assertThat(json.getInt("vulnerabilities")).isEqualTo(2);
    }

    @Test
    public void getVulnerabilityMetricsTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);
        enablePortfolioAccessControl();

        var metrics = new VulnerabilityMetrics();
        metrics.setYear(2024);
        metrics.setCount(24);
        metrics.setMeasuredAt(Date.from(Instant.now()));
        qm.persist(metrics);

        metrics = new VulnerabilityMetrics();
        metrics.setYear(2025);
        metrics.setCount(25);
        metrics.setMeasuredAt(Date.from(Instant.now()));
        qm.persist(metrics);

        final Supplier<Response> responseSupplier = () -> jersey
                .target("metrics/vulnerability")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
    }
}