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

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import io.csaf.retrieval.RetrievedDocument;
import org.dependencytrack.common.pagination.PageIterator;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * TODO: Refactor to dex workflow + activity once dex engine is integrated.
 *   * Use workflow instance ID to ensure only one workflow run per provider can exist.
 *   * Use same concurrency key across all providers to serialize their execution.
 *   * Create an "uber-workflow" that that triggers import for all providers.
 *   * Schedule the uber-workflow to run at least once daily.
 *
 * @since 5.7.0
 */
public class CsafDocumentImportTask implements Subscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsafDocumentImportTask.class);

    private final CsafClient csafClient;

    CsafDocumentImportTask(CsafClient csafClient) {
        this.csafClient = csafClient;
    }

    @SuppressWarnings("unused")
    public CsafDocumentImportTask() {
        this(new CsafClient());
    }

    @Override
    public void inform(Event e) {
        if (!(e instanceof CsafDocumentImportEvent)) {
            return;
        }

        final List<CsafProvider> providers = getEnabledProviders();
        if (providers.isEmpty()) {
            LOGGER.info("No providers available to import documents from");
            return;
        }

        for (final CsafProvider provider : providers) {
            try (var ignored = MDC.putCloseable("csafProvider", provider.getName())) {
                importDocuments(provider);
            } catch (ExecutionException | RuntimeException ex) {
                LOGGER.error("Failed to import CSAF documents", ex);
            } catch (InterruptedException ex) {
                LOGGER.warn("Interrupted while importing CSAF documents");
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private List<CsafProvider> getEnabledProviders() {
        return withJdbiHandle(handle -> {
            final var dao = handle.attach(CsafProviderDao.class);

            return PageIterator.stream(
                            pageToken -> dao.list(
                                    new ListCsafProvidersQuery()
                                            .withEnabled(true)
                                            .withPageToken(pageToken)))
                    .toList();
        });
    }

    private void importDocuments(CsafProvider provider) throws ExecutionException, InterruptedException {
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
