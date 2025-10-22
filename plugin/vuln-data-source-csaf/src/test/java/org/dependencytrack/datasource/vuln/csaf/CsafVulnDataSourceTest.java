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
import io.csaf.schema.generated.Csaf;
import io.csaf.validation.ValidationException;
import kotlinx.serialization.json.Json;
import org.cyclonedx.proto.v1_6.Bom;
import org.intellij.lang.annotations.Language;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CsafVulnDataSourceTest {

    private SourcesManager sourcesManagerMock;
    private CsafLoader csafLoaderMock;
    private CsafVulnDataSource dataSource;

    @BeforeEach
    void setUp() {
        sourcesManagerMock = mock(SourcesManager.class);
        csafLoaderMock = mock(CsafLoader.class);
    }

    @Test
    void testHasNextWithNoProviders() {
        // Given: no enabled providers
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of());
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

        // When & Then: hasNext should return false
        assertThat(dataSource.hasNext()).isFalse();
    }

    @Test
    void testHasNextWithSingleProvider() throws Exception {
        // Given: one enabled provider with documents
        var provider = createTestProvider(1, "https://example.com", true);
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        var retrievedProvider = mockRetrievedProvider(
                List.of(createMockDocument("DOC-001"))
        );

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When & Then: hasNext should return true for the first document
            assertThat(dataSource.hasNext()).isTrue();
        }
    }

    @Test
    void testNextReturnsDocument() throws Exception {
        // Given: one enabled provider with documents
        var provider = createTestProvider(1, "https://example.com", true);
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        var doc = createMockDocument("DOC-001");
        var retrievedProvider = mockRetrievedProvider(List.of(doc));

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: calling next() after hasNext()
            assertThat(dataSource.hasNext()).isTrue();
            Bom bom = dataSource.next();

            // Then: a BOM should be returned
            assertThat(bom).isNotNull();
            assertThat(bom.getPropertiesList()).isNotEmpty();
        }
    }

    @Test
    void testNextWithoutHasNextThrowsException() throws Exception {
        // Given: one enabled provider with no documents
        CsafSource provider = createTestProvider(1, "https://example.com", true);
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        RetrievedProvider retrievedProvider = mockRetrievedProvider(List.of());

        try (MockedStatic<RetrievedProvider> mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When & Then: calling next() without hasNext() should throw
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> dataSource.next());
        }
    }

    @Test
    void testMultipleProvidersIteratedSequentially() throws Exception {
        // Given: two enabled providers with one document each
        var provider1 = createTestProvider(1, "https://provider1.com", true);
        var provider2 = createTestProvider(2, "https://provider2.com", true);
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider1, provider2));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        var retrievedProvider1 = mockRetrievedProvider(
                List.of(createMockDocument("DOC-001"))
        );
        var retrievedProvider2 = mockRetrievedProvider(
                List.of(createMockDocument("DOC-002"))
        );

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://provider1.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider1));
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://provider2.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider2));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: iterating through all documents
            int count = 0;
            while (dataSource.hasNext()) {
                dataSource.next();
                count++;
            }

            // Then: should have processed 2 documents (one from each provider)
            assertThat(count).isEqualTo(2);
        }
    }

    @Test
    void testMarkProcessedAdvancesWatermark() throws Exception {
        // Given: one enabled provider
        var provider = createTestProvider(42, "https://example.com", true);
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        var doc = createMockDocument("DOC-001");
        var retrievedProvider = mockRetrievedProvider(List.of(doc));

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: getting and marking a document as processed
            assertThat(dataSource.hasNext()).isTrue();
            Bom bom = dataSource.next();
            dataSource.markProcessed(bom);

            // Then: the watermark should be advanced
            ArgumentCaptor<Integer> idCaptor = ArgumentCaptor.forClass(Integer.class);
            ArgumentCaptor<java.time.Instant> instantCaptor = ArgumentCaptor.forClass(java.time.Instant.class);
            verify(sourcesManagerMock).maybeAdvance(idCaptor.capture(), instantCaptor.capture());

            assertThat(idCaptor.getValue()).isEqualTo(42);
            assertThat(instantCaptor.getValue()).isNotNull();
        }
    }

    @Test
    void testMarkProcessedWithNullBomThrowsException() {
        // Given: a data source
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of());
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());
        dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

        // When & Then: marking null as processed should throw
        assertThatThrownBy(() -> dataSource.markProcessed(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void testMarkProcessedWithInvalidBomThrowsException() {
        // Given: a data source and a BOM without required properties
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of());
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());
        dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

        Bom invalidBom = Bom.newBuilder().build();

        // When & Then: marking invalid BOM should throw
        assertThatThrownBy(() -> dataSource.markProcessed(invalidBom))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testCloseCommitsChanges() {
        // Given: a data source
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of());
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());
        dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

        // When: closing the data source
        dataSource.close();

        // Then: changes should be committed
        verify(sourcesManagerMock).maybeCommit();
    }

    @Test
    void testDomainProviderUsesCorrectRetrievalMethod() throws Exception {
        // Given: a domain-based provider
        var domainProvider = createTestProvider(1, "example.com", true);
        domainProvider.setDomain(true);

        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(domainProvider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        var retrievedProvider = mockRetrievedProvider(List.of());

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromDomainAsync(eq("example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: opening the provider
            assertThat(dataSource.hasNext()).isFalse();

            // Then: should use domain-based retrieval
            mockedStatic.verify(() -> RetrievedProvider.fromDomainAsync(eq("example.com"), any(CsafLoader.class)));
            mockedStatic.verify(() -> RetrievedProvider.fromUrlAsync(any(), any()), never());
        }
    }

    @SuppressWarnings("ConstantValue")
    @Test
    void testDiscoveryOnlyRunsOnce() throws Exception {
        // Given: an aggregator
        var aggregator = createTestAggregator(1, "https://aggregator.com", true);
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of(aggregator));
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of());

        var retrievedAggregator = mockRetrievedAggregator();

        try (final var mockedStatic = mockStatic(RetrievedAggregator.class)) {
            mockedStatic.when(() -> RetrievedAggregator.fromUrlAsync(eq("https://aggregator.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedAggregator));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: calling hasNext multiple times
            assertThat(dataSource.hasNext()).isFalse();
            assertThat(dataSource.hasNext()).isFalse();
            assertThat(dataSource.hasNext()).isFalse();

            // Then: aggregator should only be retrieved once
            mockedStatic.verify(() -> RetrievedAggregator.fromUrlAsync(eq("https://aggregator.com"), any(CsafLoader.class)), times(1));
        }
    }

    @Test
    void testDisabledAggregatorIsNotProcessed() throws Exception {
        // Given: a disabled aggregator
        var disabledAggregator = createTestAggregator(1, "https://aggregator.com", false);
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of(disabledAggregator));
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of());

        try (final var mockedStatic = mockStatic(RetrievedAggregator.class)) {
            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: discovery runs
            assertThat(dataSource.hasNext()).isFalse();

            // Then: disabled aggregator should not be retrieved
            mockedStatic.verifyNoInteractions();
        }
    }

    @Test
    void testSkipsFailedDocuments() throws Exception {
        // Given: a provider with one failed and one successful document
        var provider = createTestProvider(1, "https://example.com", true);
        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        @SuppressWarnings("unchecked")
        ResultCompat<RetrievedDocument> failedResult = mock(ResultCompat.class);
        when(failedResult.isFailure()).thenReturn(true);
        when(failedResult.getOrNull()).thenReturn(null);
        when(failedResult.exceptionOrNull()).thenReturn(new ValidationException(List.of("Invalid CSAF document")));

        var successResult = createSuccessResult(createMockDocument("DOC-002"));
        var retrievedProvider = mockRetrievedProviderWithResults(
                List.of(failedResult, successResult)
        );

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: iterating through documents
            int count = 0;
            while (dataSource.hasNext()) {
                Bom bom = dataSource.next();
                assertThat(bom).isNotNull();
                count++;
            }

            // Then: only the successful document should be returned
            assertThat(count).isEqualTo(1);
        }
    }

    @Test
    void testProviderWithLastFetchedTimestamp() throws Exception {
        // Given: a provider with a lastFetched timestamp
        var lastFetched = java.time.Instant.parse("2024-01-01T00:00:00Z");
        var provider = createTestProvider(1, "https://example.com", true);
        provider.setLastFetched(lastFetched);

        when(sourcesManagerMock.listProviders(any())).thenReturn(List.of(provider));
        when(sourcesManagerMock.listAggregators()).thenReturn(List.of());

        var retrievedProvider = mockRetrievedProvider(List.of());

        try (final var mockedStatic = mockStatic(RetrievedProvider.class)) {
            mockedStatic.when(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)))
                    .thenReturn(CompletableFuture.completedFuture(retrievedProvider));

            dataSource = new CsafVulnDataSource(sourcesManagerMock, csafLoaderMock);

            // When: opening the provider
            assertThat(dataSource.hasNext()).isFalse();

            // Then: the provider should be retrieved (streamDocuments will be called with 'since' parameter)
            mockedStatic.verify(() -> RetrievedProvider.fromUrlAsync(eq("https://example.com"), any(CsafLoader.class)));
        }
    }

    // ========== Helper Methods ==========

    private CsafSource createTestProvider(int id, String url, boolean enabled) {
        var source = new CsafSource(
                "Test Provider",
                url,
                false, // not an aggregator
                false, // not discovered
                enabled,
                false  // not a domain
        );
        source.setId(id);
        return source;
    }

    private CsafSource createTestAggregator(int id, String url, boolean enabled) {
        var source = new CsafSource(
                "Test Aggregator",
                url,
                true,  // is an aggregator
                false, // not discovered
                enabled,
                false  // not a domain
        );
        source.setId(id);
        return source;
    }

    private RetrievedDocument createMockDocument(String trackingId) {
        var doc = mock(RetrievedDocument.class);

        // Create a minimal CSAF document
        Csaf csaf = createMinimalCsaf(trackingId);
        when(doc.getJson()).thenReturn(csaf);
        when(doc.getUrl()).thenReturn("https://example.com/csaf/" + trackingId + ".json");

        return doc;
    }

    private Csaf createMinimalCsaf(String trackingId) {
        @Language(value = "json", prefix = "", suffix = "") var csafJson = String.format("""
                {
                  "document": {
                    "category": "csaf_base",
                    "csaf_version": "2.0",
                    "publisher": {
                      "category": "other",
                      "name": "Test Publisher",
                      "namespace": "https://example.com"
                    },
                    "title": "Test Advisory",
                    "tracking": {
                      "current_release_date": "2024-01-01T00:00:00.000Z",
                      "id": "%s",
                      "initial_release_date": "2024-01-01T00:00:00.000Z",
                      "revision_history": [
                        {
                          "date": "2024-01-01T00:00:00.000Z",
                          "number": "1",
                          "summary": "Initial version."
                        }
                      ],
                      "status": "final",
                      "version": "1"
                    }
                  }
                }
                """, trackingId);
        try {
            return Json.Default.decodeFromString(
                    Csaf.Companion.serializer(),
                    csafJson
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CSAF JSON", e);
        }
    }

    private RetrievedProvider mockRetrievedProvider(List<RetrievedDocument> documents) {
        var provider = mock(RetrievedProvider.class);
        
        var results = documents.stream()
                .map(this::createSuccessResult)
                .toList();

        // Return a new stream each time streamDocuments is called to avoid stream reuse issues
        when(provider.streamDocuments(any())).thenAnswer(invocation -> results.stream());

        return provider;
    }

    private RetrievedProvider mockRetrievedProviderWithResults(List<ResultCompat<RetrievedDocument>> results) {
        var provider = mock(RetrievedProvider.class);
        // Return a new stream each time streamDocuments is called to avoid stream reuse issues
        when(provider.streamDocuments(any())).thenAnswer(invocation -> results.stream());
        return provider;
    }

    private ResultCompat<RetrievedDocument> createSuccessResult(RetrievedDocument document) {
        @SuppressWarnings("unchecked")
        ResultCompat<RetrievedDocument> result = mock(ResultCompat.class);
        when(result.isFailure()).thenReturn(false);
        when(result.getOrNull()).thenReturn(document);
        return result;
    }

    private RetrievedAggregator mockRetrievedAggregator() throws Exception {
        var aggregator = mock(RetrievedAggregator.class);
        
        // Mock the fetchAllAsync to return an empty list
        CompletableFuture<List<ResultCompat<RetrievedProvider>>> future = 
                CompletableFuture.completedFuture(List.of());
        when(aggregator.fetchAllAsync()).thenReturn(future);

        return aggregator;
    }
}
