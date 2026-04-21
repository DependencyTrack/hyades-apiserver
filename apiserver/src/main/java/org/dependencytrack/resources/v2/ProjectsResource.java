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

import alpine.server.auth.PermissionRequired;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.ProjectsApi;
import org.dependencytrack.api.v2.model.CloneProjectInclude;
import org.dependencytrack.api.v2.model.CloneProjectRequest;
import org.dependencytrack.api.v2.model.CloneProjectResponse;
import org.dependencytrack.api.v2.model.ListProjectAdvisoriesResponse;
import org.dependencytrack.api.v2.model.ListProjectAdvisoriesResponseItem;
import org.dependencytrack.api.v2.model.ListProjectAdvisoryFindingsResponseItem;
import org.dependencytrack.api.v2.model.ListProjectComponentsResponse;
import org.dependencytrack.api.v2.model.ListProjectComponentsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.persistence.jdbi.AdvisoryDao.ListProjectAdvisoriesRow;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.persistence.jdbi.query.ListAdvisoriesForProjectQuery;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapHashes;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;

@Provider
public class ProjectsResource extends AbstractApiResource implements ProjectsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectsResource.class);

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response listProjectComponents(UUID uuid, Boolean onlyOutdated, Boolean onlyDirect, Integer limit, String pageToken) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            var projectId = handle.attach(ProjectDao.class).getProjectId(uuid);
            if (projectId == null) {
                throw new NotFoundException();
            }
            requireProjectAccess(handle, UUID.fromString(String.valueOf(uuid)));
            final Page<Component> componentsPage = handle.attach(ComponentDao.class)
                    .listProjectComponents(projectId, onlyOutdated, onlyDirect, limit, pageToken);

            final var response = ListProjectComponentsResponse.builder()
                    .items(componentsPage.items().stream()
                            .<ListProjectComponentsResponseItem>map(
                                    componentRow -> ListProjectComponentsResponseItem.builder()
                                            .name(componentRow.getName())
                                            .hashes(mapHashes(componentRow))
                                            .classifier(componentRow.getClassifier() != null ? componentRow.getClassifier().name() : null)
                                            .copyright(componentRow.getCopyright())
                                            .cpe(componentRow.getCpe())
                                            .group(componentRow.getGroup())
                                            .internal(componentRow.isInternal())
                                            .lastInheritedRiskScore(componentRow.getLastInheritedRiskScore())
                                            .license(componentRow.getLicense())
                                            .licenseExpression(componentRow.getLicenseExpression())
                                            .licenseUrl(componentRow.getLicenseUrl())
                                            .resolvedLicense(mapLicense(componentRow.getResolvedLicense()))
                                            .occurrenceCount(componentRow.getOccurrenceCount())
                                            .purl(componentRow.getPurl().toString())
                                            .swidTagId(componentRow.getSwidTagId())
                                            .uuid(componentRow.getUuid())
                                            .version(componentRow.getVersion())
                                            .build())
                            .toList())
                    .nextPageToken(componentsPage.nextPageToken())
                    .total(convertTotalCount(componentsPage.totalCount()))
                    .build();
            return Response.ok(response).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.PORTFOLIO_MANAGEMENT)
    public Response cloneProject(final UUID projectUuid, final CloneProjectRequest request) {
        final UUID clonedProjectUuid = inJdbiTransaction(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, projectUuid);

            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Cloning project {} to version {}",
                    projectUuid,
                    request.getVersion());

            final UUID uuid = handle.attach(ProjectDao.class).cloneProject(
                    new CloneProjectCommand(
                            projectUuid,
                            request.getVersion(),
                            request.getVersionIsLatest(),
                            request.getIncludes().contains(CloneProjectInclude.ACL),
                            request.getIncludes().contains(CloneProjectInclude.COMPONENTS),
                            request.getIncludes().contains(CloneProjectInclude.FINDINGS),
                            request.getIncludes().contains(CloneProjectInclude.FINDINGS_AUDIT_HISTORY),
                            request.getIncludes().contains(CloneProjectInclude.POLICY_VIOLATIONS),
                            request.getIncludes().contains(CloneProjectInclude.POLICY_VIOLATIONS_AUDIT_HISTORY),
                            request.getIncludes().contains(CloneProjectInclude.PROPERTIES),
                            request.getIncludes().contains(CloneProjectInclude.SERVICES),
                            request.getIncludes().contains(CloneProjectInclude.TAGS)));

            requireProjectAccess(handle, uuid);
            handle.attach(MetricsDao.class).updateProjectMetrics(uuid);
            return uuid;
        });

        return Response
                .created(uriInfo.getBaseUriBuilder()
                        .path("/projects")
                        .path(clonedProjectUuid.toString())
                        .build())
                .entity(CloneProjectResponse.builder()
                        .uuid(clonedProjectUuid)
                        .build())
                .build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response listAdvisoriesForProject(UUID uuid, String pageToken, Integer limit) {
        final Page<ListProjectAdvisoriesRow> projectAdvisories =
                inJdbiTransaction(getAlpineRequest(), handle -> {
                    requireProjectAccess(handle, uuid);

                    final long projectId = handle.attach(ProjectDao.class).getProjectId(uuid);

                    return handle.attach(AdvisoryDao.class).listForProject(
                            new ListAdvisoriesForProjectQuery(projectId)
                                    .withPageToken(pageToken)
                                    .withLimit(limit));
                });

        final var responseItems = projectAdvisories.items().stream()
                .<ListProjectAdvisoriesResponseItem>map(
                        advisory -> ListProjectAdvisoriesResponseItem.builder()
                                .id(advisory.id())
                                .publisher(advisory.publisher())
                                .name(advisory.name())
                                .version(advisory.version())
                                .url(advisory.url())
                                .title(advisory.title())
                                .format(advisory.format())
                                .seenAt(advisory.seenAt() != null
                                        ? advisory.seenAt().toEpochMilli()
                                        : null)
                                .lastFetched(advisory.lastFetched() != null
                                        ? advisory.lastFetched().toEpochMilli()
                                        : null)
                                .findingsCount(advisory.findingsCount())
                                .build())
                .toList();

        final var response = ListProjectAdvisoriesResponse.builder()
                .items(responseItems)
                .nextPageToken(projectAdvisories.nextPageToken())
                .total(convertTotalCount(projectAdvisories.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProjectAdvisory(UUID uuid, UUID advisoryId) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, uuid);

            final long projectId = handle.attach(ProjectDao.class).getProjectId(uuid);

            List<AdvisoryDao.ProjectAdvisoryFindingRow> advisoryRows = handle.attach(AdvisoryDao.class)
                    .getFindingsByProjectAdvisory(projectId, advisoryId);
            final long totalCount = advisoryRows.size();

            final List<ListProjectAdvisoryFindingsResponseItem> responseItems = advisoryRows.stream()
                    .<ListProjectAdvisoryFindingsResponseItem>map(
                            row -> ListProjectAdvisoryFindingsResponseItem.builder()
                                    .name(row.name())
                                    .confidence((int) row.confidence())
                                    .desc(row.desc())
                                    .group(row.group())
                                    .version(row.version())
                                    .componentUuid(UUID.fromString(row.componentUuid()))
                                    .build())
                    .toList();

            return Response.ok(responseItems).header(TOTAL_COUNT_HEADER, totalCount).build();
        });
    }

}
