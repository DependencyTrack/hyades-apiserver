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
package org.dependencytrack.datasource.vuln.csaf;

import io.csaf.retrieval.CsafLoader;
import io.csaf.retrieval.ResultCompat;
import io.csaf.retrieval.RetrievedAggregator;
import io.csaf.retrieval.RetrievedDocument;
import io.csaf.retrieval.RetrievedProvider;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.plugin.api.datasource.vuln.VulnDataSource;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.datasource.vuln.csaf.CycloneDxPropertyNames.*;

/**
 * A Vulnerability Data Source that retrieves and processes CSAF documents from configured sources.
 *
 * @since 5.7.0
 */
public class CsafVulnDataSource implements VulnDataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsafVulnDataSource.class);

    public final SourcesManager sourcesManager;
    private boolean hasNextCalled = false;
    private boolean hasDiscovered = false;
    private final CsafLoader csafLoader;
    private final List<CsafSource> enabledProviders;
    private CsafSource currentProvider;
    private int currentProviderIndex;
    private RetrievedProvider currentRetrievedProvider;
    private Stream<ResultCompat<RetrievedDocument>> currentDocumentStream;
    private Iterator<ResultCompat<RetrievedDocument>> currentDocumentIterator;
    private Bom nextItem;
    private final Set<CsafSource> successfullyCompletedProviders;

    public CsafVulnDataSource(
            SourcesManager sourcesManager
    ) {
        this.sourcesManager = sourcesManager;
        this.csafLoader = CsafLoader.Companion.getLazyLoader();
        this.enabledProviders = sourcesManager.listProviders(CsafSource::isEnabled);
        this.successfullyCompletedProviders = new HashSet<>();
    }

    @Override
    public boolean hasNext() {
        // Try to discover new providers from aggregators before checking for advisories. Only
        // do this once per invocation of the data source.
        if (!hasDiscovered) {
            discoverProvidersFromAggregators();
            hasDiscovered = true;
        }

        if (hasNextCalled && nextItem != null) {
            return true;
        }

        hasNextCalled = true;

        if (currentDocumentIterator != null) {
            final Bom item = readNextDocument();
            if (item != null) {
                nextItem = item;
                return true;
            }

            successfullyCompletedProviders.add(currentProvider);
            LOGGER.info("Mirroring documents from CSAF provider {} completed", currentProvider.getUrl());

            closeCurrentProvider();
            currentProviderIndex++;
        }

        if (currentProviderIndex < enabledProviders.size()) {
            final boolean nextEcosystemOpened = openNextProvider();
            if (nextEcosystemOpened) {
                final Bom item = readNextDocument();
                if (item != null) {
                    nextItem = item;
                    return true;
                }
                successfullyCompletedProviders.add(currentProvider);
                LOGGER.info("Mirroring documents from CSAF provider {} completed", currentProvider.getUrl());

                closeCurrentProvider();
            }
            currentProviderIndex++;
        }

        nextItem = null;
        return false;
    }

    @Override
    public Bom next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        final Bom item = nextItem;
        nextItem = null;
        hasNextCalled = false;
        return item;
    }

    @Override
    public void markProcessed(final Bom bov) {
        requireNonNull(bov, "bov must not be null");

        final var providerId = extractProperty(bov, PROPERTY_ADVISORY_PROVIDER_ID, Integer.class);
        if (providerId == null) {
            throw new IllegalArgumentException();
        }

        final Instant updatedAt = extractProperty(bov, PROPERTY_ADVISORY_UPDATED, Instant.class);
        if (updatedAt == null) {
            throw new IllegalArgumentException();
        }

        sourcesManager.maybeAdvance(providerId, updatedAt);
    }

    @Override
    public void close() {
        sourcesManager.maybeCommit();
        closeCurrentProvider();
    }

    /**
     * Discovers new CSAF providers from all enabled aggregators.
     * <p>
     * This will call {@link SourcesManager#maybeCommit()} to commit changes if any new providers were discovered.
     */
    void discoverProvidersFromAggregators() {
        // Loop through all enabled aggregators and discover providers from them
        var aggregators = sourcesManager.listAggregators();
        for (var aggregator : aggregators) {
            try {
                discoverProvider(aggregator);
            } catch (ExecutionException | InterruptedException e) {
                LOGGER.error("Error while discovering providers from aggregator {}", aggregator.getUrl(), e);
            }
        }

        sourcesManager.maybeCommit();
    }

    /**
     * Discovers new CSAF providers from the given aggregator. This will call {@link SourcesManager#maybeDiscover(CsafSource)} for each new provider found and advance the
     * lastFetched timestamp of the aggregator if any providers were found.
     * <p>
     * This will not yet commit changes; call {@link SourcesManager#maybeCommit()} afterward if needed.
     *
     * @param aggregator the aggregator to discover providers from
     */
     void discoverProvider(CsafSource aggregator) throws ExecutionException, InterruptedException {
        // Check if this contains any providers that we don't know about yet
        final RetrievedAggregator retrieved;
        if (aggregator.isDomain()) {
            retrieved = RetrievedAggregator.fromDomainAsync(aggregator.getUrl(), this.csafLoader).get();
        } else {
            retrieved = RetrievedAggregator.fromUrlAsync(aggregator.getUrl(), this.csafLoader).get();
        }

        var begin = Instant.now();
        retrieved.fetchAllAsync().get().forEach((provider) -> {
            if (provider.getOrNull() != null) {
                var metadataJson = provider.getOrNull().getJson();
                var url = metadataJson.getCanonical_url().toString();
                var source = new CsafSource(
                        metadataJson.getPublisher().getName(),
                        url,
                        /* isAggregator */ false,
                        /* isDiscovery */ true,
                        /* isEnabled */ false,
                        /* isDomain */ false
                );
                if (sourcesManager.maybeDiscover(source)) {
                    LOGGER.info("Discovered new CSAF provider {} from retrieved {}", url, aggregator.getName());
                }
            }
        });

        sourcesManager.maybeAdvance(aggregator.getId(), begin);
    }

    /**
     * Opens the next enabled provider and initializes its document stream and iterator.
     *
     * @return true if a provider was opened, false if there are no more providers to open
     */
    boolean openNextProvider() {
        // If there are no more providers to open, return false
        if (currentProviderIndex >= enabledProviders.size()) {
            return false;
        }

        currentProvider = enabledProviders.get(currentProviderIndex);

        // Try to retrieve the provider, either as a domain or a full URL
        try {
            currentRetrievedProvider = currentProvider.isDomain()
                    ? RetrievedProvider.fromDomainAsync(currentProvider.getUrl(), this.csafLoader).get()
                    : RetrievedProvider.fromUrlAsync(currentProvider.getUrl(), this.csafLoader).get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException("Failed to retrieve provider from " + currentProvider.getUrl(), e);
        }

        // If we have a lastFetched timestamp, use it to only fetch documents updated since then
        final var since = currentProvider.getLastFetched() != null ?
                kotlinx.datetime.Instant.Companion.fromEpochMilliseconds(currentProvider.getLastFetched().toEpochMilli()) : null;

        LOGGER.info("Starting to mirror provider {} since {}", currentProvider.getUrl(), since);

        // Set up the document stream and iterator
        currentDocumentStream = currentRetrievedProvider.streamDocuments(since);
        currentDocumentIterator = currentDocumentStream.iterator();

        return true;
    }

    /**
     * Closes the current provider and its associated document stream and iterator.
     */
    void closeCurrentProvider() {
        if (currentDocumentStream != null) {
            currentDocumentStream.close();
            currentDocumentIterator = null;
        }

        currentProvider = null;
    }

    /**
     * Reads the next document from the current provider's document iterator and converts it to a CycloneDX BOM.
     *
     * @return the next CycloneDX BOM, or null if there are no more documents or if the current provider is not set
     */
    @Nullable
    Bom readNextDocument() {
        if (currentDocumentIterator == null || !currentDocumentIterator.hasNext()) {
            return null;
        }

        final ResultCompat<RetrievedDocument> result = currentDocumentIterator.next();
        return ModelConverter.convert(result, currentProvider);
    }

}
