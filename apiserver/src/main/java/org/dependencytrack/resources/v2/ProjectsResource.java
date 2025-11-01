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
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.dependencytrack.api.v2.ProjectsApi;
import org.dependencytrack.api.v2.model.CloneProjectInclude;
import org.dependencytrack.api.v2.model.CloneProjectRequest;
import org.dependencytrack.api.v2.model.CloneProjectResponse;
import org.dependencytrack.api.v2.model.ListComponentsResponse;
import org.dependencytrack.api.v2.model.ListComponentsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.command.CloneProjectCommand;
import org.dependencytrack.persistence.pagination.Page;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.pagination.PageUtil.createPaginationMetadata;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapHashes;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;

@Path("/")
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
            final Page<ComponentDao.ComponentRow> componentsPage = handle.attach(ComponentDao.class)
                    .listProjectComponents(projectId, onlyOutdated, onlyDirect, limit, pageToken);

            final var response = ListComponentsResponse.builder()
                    .components(componentsPage.items().stream()
                            .<ListComponentsResponseItem>map(
                                    componentRow -> ListComponentsResponseItem.builder()
                                            .name(componentRow.component().getName())
                                            .hashes(mapHashes(componentRow.component()))
                                            .classifier(componentRow.component().getClassifier() != null ? componentRow.component().getClassifier().name() : null)
                                            .copyright(componentRow.component().getCopyright())
                                            .cpe(componentRow.component().getCpe())
                                            .group(componentRow.component().getGroup())
                                            .internal(componentRow.component().isInternal())
                                            .lastInheritedRiskScore(componentRow.component().getLastInheritedRiskScore())
                                            .license(componentRow.component().getLicense())
                                            .licenseExpression(componentRow.component().getLicenseExpression())
                                            .licenseUrl(componentRow.component().getLicenseUrl())
                                            .resolvedLicense(mapLicense(componentRow.component().getResolvedLicense()))
                                            .occurrenceCount(componentRow.component().getOccurrenceCount())
                                            .purl(componentRow.component().getPurl().toString())
                                            .swidTagId(componentRow.component().getSwidTagId())
                                            .uuid(componentRow.component().getUuid())
                                            .version(componentRow.component().getVersion())
                                            .published(componentRow.published() != null ? componentRow.published().getEpochSecond() : null)
                                            .lastFetched(componentRow.lastFetched() != null ? componentRow.lastFetched().getEpochSecond() : null)
                                            .latestVersion(componentRow.latestVersion())
                                            .integrityCheckStatus(componentRow.integrityCheckStatus() != null ? componentRow.integrityCheckStatus().name() : null)
                                            .integrityRepoUrl(componentRow.integrityRepoUrl())
                                            .vulnerabilities(componentRow.vulnerabilities())
                                            .critical(componentRow.critical())
                                            .high(componentRow.high())
                                            .medium(componentRow.medium())
                                            .low(componentRow.low())
                                            .unassigned(componentRow.unassigned())
                                            .build())
                            .toList())
                    .pagination(createPaginationMetadata(uriInfo, componentsPage))
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

            return handle.attach(ProjectDao.class).cloneProject(
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

}
