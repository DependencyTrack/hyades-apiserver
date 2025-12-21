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
import io.csaf.retrieval.RetrievedDocument;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
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
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.csaf.CsafModelConverter;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.resources.AbstractApiResource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/**
 * API resources for advisories.
 *
 * @author Lawrence Dean
 * @author Christian Banse
 * @since 5.7.0
 */
@Path("/")
public class AdvisoriesResource extends AbstractApiResource implements AdvisoriesApi {

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
                            .lastFetched(row.lastFetched().toEpochMilli())
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

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE)
    public Response uploadAdvisory(
            String format,
            InputStream _fileInputStream) {
        try (var qm = new QueryManager(getAlpineRequest()); var uploadBuffer = new ByteArrayOutputStream()) {
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
        final var result = RetrievedDocument.fromJson(content, fileName);
        if (result.isFailure()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("The uploaded file is not a valid CSAF document: " +
                            (result.exceptionOrNull() != null
                                    ? result.exceptionOrNull().getMessage()
                                    : null))
                    .build();
        }

        return qm.callInTransaction(() -> {
            // Create a new advisory that we have already "seen" and was just fetched
            final Advisory transientAdvisory = CsafModelConverter.convert(result.getOrNull());
            transientAdvisory.setLastFetched(Instant.now());
            transientAdvisory.setSeen(true);

            final Advisory persistentAdvisory = qm.synchronizeAdvisory(transientAdvisory);

            if (transientAdvisory.getVulnerabilities() != null) {
                final var persistentVulns = new HashSet<Vulnerability>(
                        transientAdvisory.getVulnerabilities().size());
                for (final Vulnerability vuln : transientAdvisory.getVulnerabilities()) {
                    persistentVulns.add(qm.synchronizeVulnerability(vuln, false));
                }

                persistentAdvisory.setVulnerabilities(persistentVulns);
            }

            return Response.ok("File uploaded successfully: " + fileName).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE)
    public Response deleteAdvisory(String advisoryId) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
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
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            final var advisoryDao = handle.attach(AdvisoryDao.class);
            final long id;
            try {
                id = Long.parseLong(advisoryId);
            } catch (NumberFormatException e) {
                throw new NotFoundException();
            }

            // Ensure advisory exists
            // Atomically mark as seen and return the updated advisory row to avoid separate update/select
            var advisoryRow = advisoryDao.markAdvisoryAsSeenAndGet(id);
            if (advisoryRow == null) {
                throw new NotFoundException();
            }

            final ListAdvisoriesResponseItem response = ListAdvisoriesResponseItem.builder()
                    .id(advisoryRow.id())
                    .title(advisoryRow.title())
                    .url(advisoryRow.url())
                    .seen(advisoryRow.seen())
                    .lastFetched(advisoryRow.lastFetched().toEpochMilli())
                    .publisher(advisoryRow.publisher())
                    .name(advisoryRow.name())
                    .version(advisoryRow.version())
                    .affectedComponents(advisoryRow.affectedComponents())
                    .affectedProjects(advisoryRow.affectedProjects())
                    .content(advisoryRow.content())
                    .build();

            return Response.ok(response).build();
        });
    }

    @Override
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_READ)
    public Response getAdvisoryById(Long advisoryId) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
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
                            .lastFetched(advisory.lastFetched().toEpochMilli())
                            .publisher(advisory.publisher())
                            .name(advisory.name())
                            .version(advisory.version())
                            .format(advisory.format())
                            .affectedComponents(advisory.affectedComponents())
                            .affectedProjects(advisory.affectedProjects())
                            .content(advisory.content())
                            .build())
                    .affectedProjects(affectedProjects.stream()
                            .<AdvisoryProject>map(project -> AdvisoryProject.builder()
                                    .name(project.name())
                                    .uuid(UUID.fromString(project.uuid()))
                                    .desc(project.desc())
                                    .version(project.version())
                                    .build())
                            .toList())
                    .numAffectedComponents((long) advisory.affectedComponents())
                    .vulnerabilities(vulnerabilities.stream()
                            .<AdvisoryVulnerability>map(vuln -> AdvisoryVulnerability.builder()
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
                            .projectUuid(row.projectUuid())
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
