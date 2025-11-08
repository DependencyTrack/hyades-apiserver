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

import alpine.common.logging.Logger;
import alpine.server.auth.PermissionRequired;
import io.csaf.retrieval.RetrievedDocument;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.AdvisoriesApi;
import org.dependencytrack.api.v2.model.AdvisoryProject;
import org.dependencytrack.api.v2.model.AdvisoryVulnerability;
import org.dependencytrack.api.v2.model.GetAdvisoryResponse;
import org.dependencytrack.api.v2.model.ListAdvisoriesResponse;
import org.dependencytrack.api.v2.model.ListAdvisoriesResponseItem;
import org.dependencytrack.api.v2.model.ListProjectAdvisoriesResponseItem;
import org.dependencytrack.api.v2.model.ListProjectAdvisoryFindingsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.datasource.vuln.csaf.CsafSource;
import org.dependencytrack.datasource.vuln.csaf.ModelConverter;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.dependencytrack.BovModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.pagination.Page;
import org.dependencytrack.resources.AbstractApiResource;
import org.glassfish.jersey.media.multipart.FormDataParam;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.pagination.PageUtil.createPaginationMetadata;

/**
 * API resources for advisories.
 *
 * @author Lawrence Dean
 * @author Christian Banse
 * @since 5.7.0
 */
@Path("/")
public class AdvisoriesResource extends AbstractApiResource implements AdvisoriesApi {
    private static final Logger LOGGER = Logger.getLogger(AdvisoriesResource.class);

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response listAdvisories(String format, String searchText) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            // Normalize parameters: trim and treat empty as null so DAO SQL conditional
            // behaves predictably
            final String searchParam = (searchText == null || searchText.trim().isEmpty()) ? null
                    : searchText.trim();
            final String formatParam = (format == null || format.trim().isEmpty()) ? null : format.trim();

            List<AdvisoryDao.AdvisoryDetailRow> advisoryRows = handle.attach(AdvisoryDao.class)
                    .getAllAdvisories(formatParam, searchParam);
            final long totalCount = handle.attach(AdvisoryDao.class)
                    .getTotalAdvisories(formatParam, searchParam);

            final List<ListAdvisoriesResponseItem> responseItems = advisoryRows.stream()
                    .<ListAdvisoriesResponseItem>map(row -> ListAdvisoriesResponseItem.builder()
                            .id(row.id())
                            .title(row.title())
                            .url(row.url())
                            .seen(row.seen())
                            .lastFetched(row.lastFetched().atOffset(ZoneOffset.UTC).toEpochSecond()*1000)
                            .publisher(row.publisher())
                            .name(row.name())
                            .version(row.version())
                            .format(row.format())
                            .affectedComponents(row.affectedComponents())
                            .affectedProjects(row.affectedProjects())
                            .content(row.content())
                            .build())
                    .toList();

            // Create a Page object for pagination metadata (no next page token at the moment)
            final Page<ListAdvisoriesResponseItem> advisoriesPage = new Page<>(responseItems, null);

            final ListAdvisoriesResponse response = ListAdvisoriesResponse.builder()
                    .advisories(responseItems)
                    .pagination(createPaginationMetadata(getUriInfo(), advisoriesPage))
                    .build();

            return Response.ok(response).header(TOTAL_COUNT_HEADER, totalCount).build();
        });
    }

    @POST
    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE)
    public Response uploadAdvisory(
            @QueryParam("format") @NotNull String format,
            @FormDataParam("file") InputStream _fileInputStream) {
        try (var qm = new QueryManager(); var uploadBuffer = new ByteArrayOutputStream()) {
            _fileInputStream.transferTo(uploadBuffer);
            String content = uploadBuffer.toString();
            // TODO(oxisto): retrieve URL from form data again
            String fileName = "uploaded-advisory.json";

            // Process-format-specific upload
            return switch (format) {
                case "CSAF" -> processCsafDocument(content, fileName, qm);
                default -> Response.status(Response.Status.BAD_REQUEST)
                        .entity("Unsupported format: " + format).build();
            };
        } catch (IOException e) {
            throw new UncheckedIOException("File upload failed", e);
        }
    }

    /**
     * Process CSAF document content and synchronize advisory/vulnerabilities.
     * Returns a JAX-RS Response indicating success or error.
     *
     * @param content  the CSAF document content
     * @param fileName the name of the uploaded file
     * @param qm       the QueryManager to use for persistence
     * @return a JAX-RS Response indicating success or error
     */
    private Response processCsafDocument(String content, String fileName, QueryManager qm) {
        return qm.callInTransaction(() -> {
            final var result = RetrievedDocument.fromJson(content, fileName);
            if (result.isFailure()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("The uploaded file is not a valid CSAF document: " +
                                (result.exceptionOrNull() != null
                                        ? result.exceptionOrNull().getMessage()
                                        : null))
                        .build();
            }
            assert result.getOrNull() != null;
            final var doc = result.getOrNull().getJson();
            final var publisher = doc.getDocument().getPublisher().getNamespace().toString();

            // Create a new advisory that we have already "seen" and was just fetched
            final var advisory = new Advisory();
            advisory.setTitle(doc.getDocument().getTitle());
            advisory.setUrl(fileName);
            advisory.setContent(content);
            advisory.setLastFetched(Instant.now());
            advisory.setPublisher(publisher);
            advisory.setName(doc.getDocument().getTracking().getId());
            advisory.setVersion(doc.getDocument().getTracking().getVersion());
            advisory.setFormat("CSAF");
            advisory.setSeen(true);

            // Create a pseudo-source populated by the information we have
            var manual = new CsafSource();
            manual.setDomain(true);
            manual.setUrl(URI.create(publisher).getHost());
            manual.setName(publisher);

            final var bov = ModelConverter.convert(result, manual);
            for (final var v : bov.getVulnerabilitiesList()) {
                final Vulnerability vuln = BovModelConverter.convert(bov, v, true);
                final List<VulnerableSoftware> vsList = BovModelConverter
                        .extractVulnerableSoftware(bov);

                LOGGER.debug("Synchronizing vulnerability " + vuln.getVulnId());
                final Vulnerability persistentVuln = qm.synchronizeVulnerability(vuln, false);
                qm.synchronizeVulnerableSoftware(persistentVuln, vsList, Vulnerability.Source.CSAF);

                advisory.addVulnerability(persistentVuln);
            }

            // Sync the document into the database, replacing an older version with the same
            // combination of tracking ID and publisher namespace if necessary
            qm.synchronizeAdvisory(advisory);

            return Response.ok("File uploaded successfully: " + fileName).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE)
    public Response deleteAdvisory(String advisoryId) {
        try (final var qm = new QueryManager()) {
            return qm.callInTransaction(() -> {
                try {
                    final Advisory entity = qm.getObjectById(Advisory.class, advisoryId);
                    if (entity != null) {
                        qm.delete(entity);
                        return Response.status(Response.Status.NO_CONTENT).build();
                    } else {
                        throw new NotFoundException();
                    }
                } catch (javax.jdo.JDOObjectNotFoundException e) {
                    // Handle the case where the object doesn't exist
                    throw new NotFoundException();
                }
            });
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE)
    public Response markAdvisoryAsSeen(String advisoryId) {
        return inJdbiTransaction(handle -> {
            final var advisoryDao = handle.attach(AdvisoryDao.class);

            // First mark as seen using QueryManager
            try (final var qm = new QueryManager()) {
                final Advisory entity = qm.getObjectById(Advisory.class, advisoryId);
                if (entity == null) {
                    throw new NotFoundException();
                }
                entity.setSeen(true);
                qm.persist(entity);
            }

            // Then fetch the updated advisory to return
            final var advisory = advisoryDao.getAdvisoryById(Long.parseLong(advisoryId));
            if (advisory == null) {
                throw new NotFoundException();
            }

            final ListAdvisoriesResponseItem response = ListAdvisoriesResponseItem.builder()
                    .id(advisory.id())
                    .title(advisory.title())
                    .url(advisory.url())
                    .seen(advisory.seen())
                    .lastFetched(advisory.lastFetched().atOffset(ZoneOffset.UTC).toEpochSecond()*1000)
                    .publisher(advisory.publisher())
                    .name(advisory.name())
                    .version(advisory.version())
                    .affectedComponents(advisory.affectedComponents())
                    .affectedProjects(advisory.affectedProjects())
                    .content(advisory.content())
                    .build();

            return Response.ok(response).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_READ)
    public Response getAdvisoryById(Long advisoryId) {
        return inJdbiTransaction(handle -> {
            final var advisoryDao = handle.attach(AdvisoryDao.class);
            final var advisory = advisoryDao.getAdvisoryById(advisoryId);

            if (advisory == null) {
                throw new NotFoundException();
            }

            List<AdvisoryDao.ProjectRow> affectedProjects = advisoryDao.getProjectsByAdvisory(advisory.id());
            List<AdvisoryDao.VulnerabilityRow> vulnerabilities = advisoryDao
                    .getVulnerabilitiesByAdvisory(advisory.id());

            final GetAdvisoryResponse response = GetAdvisoryResponse.builder()
                    .entity(ListAdvisoriesResponseItem.builder()
                            .id(advisory.id())
                            .title(advisory.title())
                            .url(advisory.url())
                            .seen(advisory.seen())
                            .lastFetched(advisory.lastFetched().atOffset(ZoneOffset.UTC).toEpochSecond()*1000)
                            .publisher(advisory.publisher())
                            .name(advisory.name())
                            .version(advisory.version())
                            .affectedComponents(advisory.affectedComponents())
                            .affectedProjects(advisory.affectedProjects())
                            .content(advisory.content())
                            .build())
                    .affectedProjects(affectedProjects.stream()
                            .<AdvisoryProject>map(project -> AdvisoryProject.builder()
                                    .id(project.id())
                                    .name(project.name())
                                    .uuid(UUID.fromString(project.uuid()))
                                    .desc(project.desc())
                                    .version(project.version())
                                    .build())
                            .toList())
                    .numAffectedComponents((long) advisory.affectedComponents())
                    .vulnerabilities(vulnerabilities.stream()
                            .<AdvisoryVulnerability>map(vuln -> AdvisoryVulnerability.builder()
                                    .id(vuln.id())
                                    .source(vuln.source())
                                    .vulnId(vuln.vulnId())
                                    .title(vuln.title())
                                    .severity(vuln.severity())
                                    .build())
                            .toList())
                    .build();

            return Response.ok(response).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAdvisoriesByProject(UUID uuid) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            var projectId = handle.attach(ProjectDao.class).getProjectId(uuid);
            if (projectId == null) {
                throw new NotFoundException();
            }
            requireProjectAccess(handle, uuid);

            List<AdvisoryDao.AdvisoryInProjectRow> advisoryWithFindingRows = handle
                    .attach(AdvisoryDao.class)
                    .getAdvisoriesWithFindingsByProject(projectId);
            final long totalCount = advisoryWithFindingRows.size();

            final List<ListProjectAdvisoriesResponseItem> responseItems = advisoryWithFindingRows.stream()
                    .<ListProjectAdvisoriesResponseItem>map(row -> ListProjectAdvisoriesResponseItem.builder()
                            .name(row.name())
                            .projectId(row.projectId())
                            .url(row.url())
                            .documentId(row.documentId())
                            .findingsPerDoc(row.findingsPerDoc())
                            .build())
                    .toList();

            return Response.ok(responseItems)
                    .header(TOTAL_COUNT_HEADER, totalCount).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProjectAdvisory(UUID projectUuid, Long advisoryId) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            var projectId = handle.attach(ProjectDao.class).getProjectId(projectUuid);
            if (projectId == null) {
                throw new NotFoundException();
            }
            requireProjectAccess(handle, projectUuid);

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
