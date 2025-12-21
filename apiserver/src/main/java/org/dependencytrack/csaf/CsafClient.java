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

import io.csaf.retrieval.CsafLoader;
import io.csaf.retrieval.ResultCompat;
import io.csaf.retrieval.RetrievedAggregator;
import io.csaf.retrieval.RetrievedDocument;
import io.csaf.retrieval.RetrievedProvider;
import org.dependencytrack.common.ProxySelector;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;

import static io.csaf.retrieval.CsafLoaderJvmKt.javaClientEngine;
import static java.util.Objects.requireNonNull;

/**
 * Thin wrapper around the CSAF Kotlin library, mostly to enable mocking.
 *
 * @since 5.7.0
 */
class CsafClient {

    private final CsafLoader csafLoader;

    CsafClient() {
        this.csafLoader = CsafLoader.withSettings(
                /* maxRetries */ 5,
                /* retryBase */ 1000,
                /* retryBaseDelayMs */ 5000,
                /* retryMaxDelayMs */ 60000,
                javaClientEngine(new ProxySelector()));
    }

    Stream<CsafProvider> discoverProviders(CsafAggregator aggregator) throws ExecutionException, InterruptedException {
        requireNonNull(aggregator, "aggregator must not be null");

        final RetrievedAggregator retrievedAggregator =
                RetrievedAggregator.fromUrlAsync(
                        aggregator.getUrl().toString(), csafLoader).get();

        return retrievedAggregator.fetchProvidersAsync().get().stream()
                .map(ResultCompat::getOrNull)
                .filter(Objects::nonNull)
                .map(discoveredProvider -> new CsafProvider(
                        URI.create(discoveredProvider.getJson().getCanonical_url().toString()),
                        URI.create(discoveredProvider.getJson().getPublisher().getNamespace().toString()),
                        discoveredProvider.getJson().getPublisher().getName()));
    }

    Stream<RetrievedDocument> getDocuments(CsafProvider provider, @Nullable Instant since) throws ExecutionException, InterruptedException {
        final RetrievedProvider retrievedProvider =
                RetrievedProvider.fromUrlAsync(provider.getUrl().toString(), csafLoader).get();

        final var kotlinSince = since != null
                ? kotlinx.datetime.Instant.Companion.fromEpochMilliseconds(since.toEpochMilli())
                : null;

        return retrievedProvider.streamDocuments(kotlinSince, csafLoader)
                .map(ResultCompat::getOrNull)
                .filter(Objects::nonNull);
    }

}
