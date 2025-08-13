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
import org.dependencytrack.api.v2.model.ListComponentsResponse;
import org.dependencytrack.api.v2.model.ListComponentsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.persistence.jdbi.ComponentDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.pagination.Page;
import org.dependencytrack.resources.v1.AbstractApiResource;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.pagination.PageUtil.createPaginationMetadata;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapHashes;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;

@Provider
public class ProjectsResource extends AbstractApiResource implements ProjectsApi {

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

            final var response = ListComponentsResponse.builder()
                    .components(componentsPage.items().stream()
                            .<ListComponentsResponseItem>map(
                                    componentRow -> ListComponentsResponseItem.builder()
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
                    .pagination(createPaginationMetadata(uriInfo, componentsPage))
                    .build();
            return Response.ok(response).build();
        });
    }
}
