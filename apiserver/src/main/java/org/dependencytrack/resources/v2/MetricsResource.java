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

import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.MetricsApi;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.MetricsDao;

import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class MetricsResource implements MetricsApi {

    @Override
    public Response getPortfolioCurrentMetrics() {
        PortfolioMetrics metrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        return Response.ok(metrics).build();
    }

    @Override
    public Response getVulnerabilityMetrics() {
        try (QueryManager qm = new QueryManager()) {
            final List<VulnerabilityMetrics> metrics = qm.getVulnerabilityMetrics();
            return Response.ok(metrics).build();
        }
    }
}
