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
package org.dependencytrack.csaf;

import io.csaf.retrieval.RetrievedDocument;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.internal.workflow.v1.ImportCsafDocumentsArg;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "import-csaf-documents")
public final class ImportCsafDocumentsActivity implements Activity<ImportCsafDocumentsArg, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ImportCsafDocumentsActivity.class);

    private final CsafClient csafClient;

    ImportCsafDocumentsActivity(CsafClient csafClient) {
        this.csafClient = csafClient;
    }

    public ImportCsafDocumentsActivity() {
        this(new CsafClient());
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable ImportCsafDocumentsArg arg) throws Exception {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final CsafProvider provider = withJdbiHandle(
                handle -> handle.attach(CsafProviderDao.class).getById(UUID.fromString(arg.getProviderId())));
        if (provider == null) {
            throw new TerminalApplicationFailureException(
                    "Provider with ID %s does not exist".formatted(arg.getProviderId()));
        }

        try (var ignored = MDC.putCloseable("csafProvider", provider.getName())) {
            if (!provider.isEnabled()) {
                LOGGER.info("Provider is disabled");
                return null;
            }

            importDocuments(ctx, provider);
        }

        return null;
    }

    private void importDocuments(
            ActivityContext ctx,
            CsafProvider provider) throws ExecutionException, InterruptedException {
        Instant latestDocumentReleaseDate = provider.getLatestDocumentReleaseDate();
        if (latestDocumentReleaseDate != null) {
            LOGGER.info("Importing CSAF documents modified since {}", latestDocumentReleaseDate);
        } else {
            LOGGER.info("Importing CSAF documents");
        }

        try (final Stream<RetrievedDocument> documentStream =
                     csafClient.getDocuments(provider, latestDocumentReleaseDate)) {
            final Iterator<RetrievedDocument> documentIterator = documentStream.iterator();

            final var documentBatch = new ArrayList<RetrievedDocument>(25);
            while (documentIterator.hasNext()) {
                final RetrievedDocument doc = documentIterator.next();
                ctx.maybeHeartbeat();

                final Instant docReleaseDate = doc.getJson().getDocument().getTracking().getCurrent_release_date().getValue$kotlinx_datetime();
                if (latestDocumentReleaseDate == null || latestDocumentReleaseDate.isBefore(docReleaseDate)) {
                    latestDocumentReleaseDate = docReleaseDate;
                }

                documentBatch.add(doc);
                if (documentBatch.size() == 25) {
                    processDocuments(documentBatch);
                    documentBatch.clear();
                }
            }

            if (!documentBatch.isEmpty()) {
                ctx.maybeHeartbeat();
                processDocuments(documentBatch);
                documentBatch.clear();
            }
        }

        // NB: It's unclear in what order documents are fetched,
        // and whether that order is a guarantee or just coincidence.
        // We thus only update the latest release date at the very end,
        // when all documents were imported successfully.
        if (latestDocumentReleaseDate != null) {
            try (final Handle jdbiHandle = openJdbiHandle()) {
                final var dao = jdbiHandle.attach(CsafProviderDao.class);
                dao.updateLatestDocumentReleaseDateById(provider.getId(), latestDocumentReleaseDate);
            }
        }
    }

    private void processDocuments(List<RetrievedDocument> documents) {
        LOGGER.debug("Processing batch of {} documents", documents.size());

        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");

            qm.runInTransaction(() -> {
                for (final RetrievedDocument document : documents) {
                    processDocument(qm, document);
                }
            });
        }

    }

    private void processDocument(QueryManager qm, RetrievedDocument document) {
        final Advisory transientAdvisory = CsafModelConverter.convert(document);

        final Advisory persistentAdvisory = qm.synchronizeAdvisory(transientAdvisory);

        if (transientAdvisory.getVulnerabilities() != null) {
            final var persistentVulns = new HashSet<Vulnerability>(
                    transientAdvisory.getVulnerabilities().size());
            for (final Vulnerability vuln : transientAdvisory.getVulnerabilities()) {
                persistentVulns.add(qm.synchronizeVulnerability(vuln, false));
            }

            persistentAdvisory.setVulnerabilities(persistentVulns);
        }

    }

}
