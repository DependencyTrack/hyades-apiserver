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
import com.github.packageurl.MalformedPackageURLException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.api.v2.ComponentsApi;
import org.dependencytrack.api.v2.model.CreateComponentRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.ComponentVulnerabilityAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.componentmeta.ComponentProjection;
import org.dependencytrack.event.kafka.componentmeta.Handler;
import org.dependencytrack.event.kafka.componentmeta.HandlerFactory;
import org.dependencytrack.exception.ProjectAccessDeniedException;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.VulnerabilityScanDao;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;
import org.dependencytrack.resources.v1.AbstractApiResource;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;
import org.jdbi.v3.core.Handle;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.UUID;

import static org.dependencytrack.event.kafka.componentmeta.IntegrityCheck.calculateIntegrityResult;
import static org.dependencytrack.model.FetchStatus.NOT_AVAILABLE;
import static org.dependencytrack.model.FetchStatus.PROCESSED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.createLocalJdbi;
import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapOrganizationalContacts;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

@Provider
public class ComponentsResource extends AbstractApiResource implements ComponentsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComponentsResource.class);
    private final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response createComponent(final CreateComponentRequest request) {
        final UUID projectUuid = request.getProjectUuid();
        try (QueryManager qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    throw new NotFoundException();
                }
                try {
                    requireAccess(qm, project);
                } catch (ProjectAccessDeniedException ex) {
                    throw new NotAuthorizedException(Response.Status.UNAUTHORIZED);
                }

                final License resolvedLicense = qm.getLicense(request.getLicense());
                final Component component = new Component();
                component.setProject(project);
                if (request.getAuthors() != null) {
                    component.setAuthors(mapOrganizationalContacts(request.getAuthors()));
                }
                component.setPublisher(StringUtils.trimToNull(request.getPublisher()));
                component.setName(StringUtils.trimToNull(request.getName()));
                component.setVersion(StringUtils.trimToNull(request.getVersion()));
                component.setGroup(StringUtils.trimToNull(request.getGroup()));
                component.setDescription(StringUtils.trimToNull(request.getDescription()));
                component.setFilename(StringUtils.trimToNull(request.getFilename()));
                if (request.getClassifier() != null) {
                    component.setClassifier(Classifier.valueOf(request.getClassifier().name()));
                }
                component.setPurl(request.getPurl());
                component.setPurlCoordinates(PurlUtil.silentPurlCoordinatesOnly(component.getPurl()));
                component.setInternal(new InternalComponentIdentifier().isInternal(component));
                component.setCpe(StringUtils.trimToNull(request.getCpe()));
                component.setSwidTagId(StringUtils.trimToNull(request.getSwidTagId()));
                component.setCopyright(StringUtils.trimToNull(request.getCopyright()));
                if (request.getHashes() != null) {
                    component.setMd5(StringUtils.trimToNull(request.getHashes().getMd5()));
                    component.setSha1(StringUtils.trimToNull(request.getHashes().getSha1()));
                    component.setSha256(StringUtils.trimToNull(request.getHashes().getSha256()));
                    component.setSha384(StringUtils.trimToNull(request.getHashes().getSha384()));
                    component.setSha512(StringUtils.trimToNull(request.getHashes().getSha512()));
                    component.setSha3_256(StringUtils.trimToNull(request.getHashes().getSha3256()));
                    component.setSha3_384(StringUtils.trimToNull(request.getHashes().getSha3384()));
                    component.setSha3_512(StringUtils.trimToNull(request.getHashes().getSha3512()));
                }
                if (resolvedLicense != null) {
                    component.setLicense(null);
                    component.setLicenseExpression(null);
                    component.setLicenseUrl(StringUtils.trimToNull(request.getLicenseUrl()));
                    component.setResolvedLicense(resolvedLicense);
                } else if (StringUtils.isNotBlank(request.getLicense())) {
                    component.setLicense(StringUtils.trim(request.getLicense()));
                    component.setLicenseExpression(null);
                    component.setLicenseUrl(StringUtils.trimToNull(request.getLicenseUrl()));
                    component.setResolvedLicense(null);
                } else if (StringUtils.isNotBlank(request.getLicenseExpression())) {
                    component.setLicense(null);
                    component.setLicenseExpression(StringUtils.trim(request.getLicenseExpression()));
                    component.setLicenseUrl(null);
                    component.setResolvedLicense(null);
                }

                if (request.getParentUuid() != null) {
                    Component parent = qm.getObjectByUuid(Component.class, request.getParentUuid());
                    component.setParent(parent);
                }
                component.setNotes(StringUtils.trimToNull(request.getNotes()));

                qm.createComponent(component, true);

                if (component.getPurl() != null) {
                    ComponentProjection componentProjection =
                            new ComponentProjection(component.getUuid(), component.getPurlCoordinates().toString(),
                                    component.isInternal(), component.getPurl());
                    try {
                        Handler repoMetaHandler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, FetchMeta.FETCH_META_INTEGRITY_DATA_AND_LATEST_VERSION);
                        IntegrityMetaComponent integrityMetaComponent = repoMetaHandler.handle();
                        if (integrityMetaComponent != null && (integrityMetaComponent.getStatus() == PROCESSED || integrityMetaComponent.getStatus() == NOT_AVAILABLE)) {
                            calculateIntegrityResult(integrityMetaComponent, component, qm);
                        }
                    } catch (MalformedPackageURLException ex) {
                        LOGGER.warn("Unable to process package url %s".formatted(componentProjection.purl()));
                    }
                }

                try (final Handle jdbiHandle = createLocalJdbi(qm).open()) {
                    final var vulnAnalysisEvent = new ComponentVulnerabilityAnalysisEvent(UUID.randomUUID(), component, VulnerabilityAnalysisLevel.MANUAL_ANALYSIS, true);
                    jdbiHandle.attach(VulnerabilityScanDao.class).createVulnerabilityScan(
                            VulnerabilityScan.TargetType.COMPONENT.name(), component.getUuid(), vulnAnalysisEvent.token(), 1, Instant.now());
                    kafkaEventDispatcher.dispatchEvent(vulnAnalysisEvent);
                }

                LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Component created: {}", request.getName());
                return Response
                        .created(uriInfo.getBaseUriBuilder()
                                .path("/components/project/")
                                .path(projectUuid.toString())
                                .build())
                        .build();
            });
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new ClientErrorException(Response.Status.CONFLICT);
            }
            throw e;
        }
    }
}
