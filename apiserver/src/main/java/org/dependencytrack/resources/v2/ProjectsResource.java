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
import alpine.server.resources.AlpineResource;
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

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.pagination.PageUtil.createPaginationMetadata;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapExternalReferences;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapLicense;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapOrganizationContacts;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapOrganizationEntity;

@Provider
public class ProjectsResource extends AlpineResource implements ProjectsApi {

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getProjectComponents(UUID uuid, Boolean onlyOutdated, Boolean onlyDirect, Integer limit, String pageToken) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            var projectId = handle.attach(ProjectDao.class).getProjectId(UUID.fromString(String.valueOf(uuid)));
            if (projectId == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
            final Page<Component> componentsPage = handle.attach(ComponentDao.class)
                    .getComponentsForProject(projectId, onlyOutdated, onlyDirect, limit, pageToken);

            final var response = ListComponentsResponse.builder()
                    .components(componentsPage.items().stream()
                            .<ListComponentsResponseItem>map(
                                    componentRow -> ListComponentsResponseItem.builder()
                                            .name(componentRow.getName())
                                            .authors(mapOrganizationContacts(componentRow.getAuthors()))
                                            .blake2b256(componentRow.getBlake2b_256())
                                            .blake2b384(componentRow.getBlake2b_384())
                                            .blake2b512(componentRow.getBlake2b_512())
                                            .blake3(componentRow.getBlake3())
                                            .classifier(componentRow.getClassifier().name())
                                            .copyright(componentRow.getCopyright())
                                            .cpe(componentRow.getCpe())
                                            .description(componentRow.getDescription())
                                            .directDependencies(componentRow.getDirectDependencies())
                                            .extension(componentRow.getExtension())
                                            .externalReferences(mapExternalReferences(componentRow.getExternalReferences()))
                                            .filename(componentRow.getFilename())
                                            .group(componentRow.getGroup())
                                            .internal(componentRow.isInternal())
                                            .lastInheritedRiskScore(componentRow.getLastInheritedRiskScore())
                                            .license(componentRow.getLicense())
                                            .licenseExpression(componentRow.getLicenseExpression())
                                            .licenseUrl(componentRow.getLicenseUrl())
                                            .resolvedLicense(mapLicense(componentRow.getResolvedLicense()))
                                            .occurrenceCount(componentRow.getOccurrenceCount())
                                            .publisher(componentRow.getPublisher())
                                            .purl(componentRow.getPurl().toString())
                                            .purlCoordinates(componentRow.getPurlCoordinates().getCoordinates())
                                            .sha1(componentRow.getSha1())
                                            .sha256(componentRow.getSha256())
                                            .sha384(componentRow.getSha384())
                                            .sha512(componentRow.getSha512())
                                            .sha3256(componentRow.getSha3_256())
                                            .sha3384(componentRow.getSha3_384())
                                            .sha3512(componentRow.getSha3_512())
                                            .supplier(mapOrganizationEntity(componentRow.getSupplier()))
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
