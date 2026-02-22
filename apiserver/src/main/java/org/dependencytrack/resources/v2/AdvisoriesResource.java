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
import org.dependencytrack.api.v2.model.GetAdvisoryResponse;
import org.dependencytrack.api.v2.model.ListAdvisoriesResponse;
import org.dependencytrack.api.v2.model.ListAdvisoriesResponseItem;
import org.dependencytrack.api.v2.model.ListProjectAdvisoriesResponse;
import org.dependencytrack.api.v2.model.ListProjectAdvisoriesResponseItem;
import org.dependencytrack.api.v2.model.ListProjectAdvisoryFindingsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.csaf.CsafModelConverter;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.persistence.jdbi.AdvisoryDao.AdvisoryDetailRow;
import org.dependencytrack.persistence.jdbi.AdvisoryDao.ListAdvisoriesRow;
import org.dependencytrack.persistence.jdbi.AdvisoryDao.ListProjectAdvisoriesRow;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.query.ListAdvisoriesForProjectQuery;
import org.dependencytrack.persistence.jdbi.query.ListAdvisoriesQuery;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * API resources for advisories.
 *
 * @author Lawrence Dean
 * @author Christian Banse
 * @since 5.7.0
 */
@Path("/")
public class AdvisoriesResource extends AbstractApiResource implements AdvisoriesApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdvisoriesResource.class);

    @Override
    @PermissionRequired({
            Permissions.Constants.VULNERABILITY_MANAGEMENT,
            Permissions.Constants.VULNERABILITY_MANAGEMENT_READ
    })
    public Response listAdvisories(String format, String searchText, String pageToken, Integer limit) {
        final Page<ListAdvisoriesRow> advisoriesPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(AdvisoryDao.class).list(
                        new ListAdvisoriesQuery()
                                .withFormat(format)
                                .withSearchText(searchText)
                                .withPageToken(pageToken)
                                .withLimit(limit)));

        final var responseItems = advisoriesPage.items().stream()
                .<ListAdvisoriesResponseItem>map(
                        advisory -> ListAdvisoriesResponseItem.builder()
                                .id(advisory.id())
                                .title(advisory.title())
                                .url(advisory.url())
                                .seenAt(advisory.seenAt() != null
                                        ? advisory.seenAt().toEpochMilli()
                                        : null)
                                .lastFetched(advisory.lastFetched().toEpochMilli())
                                .publisher(advisory.publisher())
                                .name(advisory.name())
                                .version(advisory.version())
                                .format(advisory.format())
                                .affectedComponentCount(advisory.affectedComponentCount())
                                .affectedProjectCount(advisory.affectedProjectCount())
                                .build())
                .toList();

        final var response = ListAdvisoriesResponse.builder()
                .items(responseItems)
                .nextPageToken(advisoriesPage.nextPageToken())
                .total(convertTotalCount(advisoriesPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.VULNERABILITY_MANAGEMENT,
            Permissions.Constants.VULNERABILITY_MANAGEMENT_CREATE
    })
    public Response uploadAdvisory(
            String format,
            InputStream _fileInputStream) {
        try (var qm = new QueryManager(getAlpineRequest());
             var uploadBuffer = new ByteArrayOutputStream()) {
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
            transientAdvisory.setSeenAt(Instant.now());

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
    @PermissionRequired({
            Permissions.Constants.VULNERABILITY_MANAGEMENT,
            Permissions.Constants.VULNERABILITY_MANAGEMENT_DELETE
    })
    public Response deleteAdvisory(UUID id) {
        final boolean deleted = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(AdvisoryDao.class).deleteById(id));

        if (!deleted) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted advisory {}", id);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.VULNERABILITY_MANAGEMENT,
            Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE
    })
    public Response markAdvisoryAsSeen(UUID id) {
        final boolean updated = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(AdvisoryDao.class).markAsSeen(id));

        if (!updated) {
            throw new NotFoundException();
        }

        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.VULNERABILITY_MANAGEMENT,
            Permissions.Constants.VULNERABILITY_MANAGEMENT_READ
    })
    public Response getAdvisoryById(UUID id) {
        final AdvisoryDetailRow advisory = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(AdvisoryDao.class).getById(id));

        if (advisory == null) {
            throw new NotFoundException();
        }

        final GetAdvisoryResponse response = GetAdvisoryResponse.builder()
                .id(advisory.id())
                .title(advisory.title())
                .url(advisory.url())
                .seenAt(advisory.seenAt() != null
                        ? advisory.seenAt().toEpochMilli()
                        : null)
                .lastFetched(advisory.lastFetched().toEpochMilli())
                .publisher(advisory.publisher())
                .name(advisory.name())
                .version(advisory.version())
                .format(advisory.format())
                .affectedComponentCount(advisory.affectedComponentCount())
                .affectedProjectCount(advisory.affectedProjectCount())
                .content(advisory.content())
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response listAdvisoriesForProject(UUID projectUuid, String pageToken, Integer limit) {
        final Page<ListProjectAdvisoriesRow> projectAdvisories =
                inJdbiTransaction(getAlpineRequest(), handle -> {
                    requireProjectAccess(handle, projectUuid);

                    final long projectId = handle.attach(ProjectDao.class).getProjectId(projectUuid);

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

    // TODO: What is the purpose of this endpoint? Do we really need it?
    //  Can we include this in a more general /findings endpoint and add a filter option
    //  for advisories, e.g. `/findings?project_uuid=foo&advisory_id=bar`?
    @Override
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProjectAdvisory(UUID projectUuid, UUID advisoryId) {
        return inJdbiTransaction(getAlpineRequest(), handle -> {
            requireProjectAccess(handle, projectUuid);

            final long projectId = handle.attach(ProjectDao.class).getProjectId(projectUuid);

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
