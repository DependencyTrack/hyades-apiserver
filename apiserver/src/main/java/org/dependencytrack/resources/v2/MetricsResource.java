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

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.dependencytrack.api.v2.MetricsApi;
import org.dependencytrack.api.v2.model.ListVulnerabilityMetricsResponse;
import org.dependencytrack.api.v2.model.ListVulnerabilityMetricsResponseItem;
import org.dependencytrack.api.v2.model.PortfolioMetricsResponse;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.pagination.Page;

import java.time.ZoneOffset;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.util.PageUtil.createPaginationMetadata;

public class MetricsResource implements MetricsApi {

    @Context
    private UriInfo uriInfo;

    @Override
    public Response getPortfolioCurrentMetrics() {
        PortfolioMetrics metrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        final var response = PortfolioMetricsResponse.builder()
                .components(metrics.getComponents())
                .critical(metrics.getCritical())
                .findingsAudited(metrics.getFindingsAudited())
                .findingsTotal(metrics.getFindingsTotal())
                .findingsUnaudited(metrics.getFindingsUnaudited())
                .high(metrics.getHigh())
                .inheritedRiskScore(metrics.getInheritedRiskScore())
                .lastOccurrence(metrics.getLastOccurrence().toInstant().atOffset(ZoneOffset.UTC))
                .low(metrics.getLow())
                .medium(metrics.getMedium())
                .policyViolationsAudited(metrics.getPolicyViolationsAudited())
                .policyViolationsFail(metrics.getPolicyViolationsFail())
                .policyViolationsInfo(metrics.getPolicyViolationsInfo())
                .policyViolationsLicenseAudited(metrics.getPolicyViolationsLicenseAudited())
                .policyViolationsLicenseTotal(metrics.getPolicyViolationsLicenseTotal())
                .policyViolationsLicenseUnaudited(metrics.getPolicyViolationsLicenseUnaudited())
                .policyViolationsOperationalAudited(metrics.getPolicyViolationsOperationalAudited())
                .policyViolationsOperationalTotal(metrics.getPolicyViolationsOperationalTotal())
                .policyViolationsOperationalUnaudited(metrics.getPolicyViolationsOperationalUnaudited())
                .policyViolationsSecurityAudited(metrics.getPolicyViolationsSecurityAudited())
                .policyViolationsSecurityTotal(metrics.getPolicyViolationsSecurityTotal())
                .policyViolationsSecurityUnaudited(metrics.getPolicyViolationsSecurityUnaudited())
                .policyViolationsTotal(metrics.getPolicyViolationsTotal())
                .policyViolationsUnaudited(metrics.getPolicyViolationsUnaudited())
                .policyViolationsWarn(metrics.getPolicyViolationsWarn())
                .projects(metrics.getProjects())
                .suppressed(metrics.getSuppressed())
                .unassigned(metrics.getUnassigned())
                .vulnerabilities(metrics.getVulnerabilities())
                .vulnerableComponents(metrics.getVulnerableComponents())
                .vulnerableProjects(metrics.getVulnerableProjects())
                .build();
        return Response.ok(response).build();
    }

    @Override
    public Response getVulnerabilityMetrics(Integer limit, String pageToken) {
        final Page<MetricsDao.ListVulnerabilityMetricsRow> metricsPage = inJdbiTransaction(
                handle -> handle.attach(MetricsDao.class).getVulnerabilityMetrics(limit, pageToken));

        final var response = ListVulnerabilityMetricsResponse.builder()
                .metrics(metricsPage.items().stream()
                        .<ListVulnerabilityMetricsResponseItem>map(
                                metricRow -> ListVulnerabilityMetricsResponseItem.builder()
                                        .year(metricRow.year())
                                        .month(metricRow.month())
                                        .count(metricRow.count())
                                        .measuredAt(metricRow.measuredAt().atOffset(ZoneOffset.UTC))
                                        .build())
                        .toList())
                .pagination(createPaginationMetadata(uriInfo, metricsPage))
                .build();

        return Response.ok(response).build();
    }
}
