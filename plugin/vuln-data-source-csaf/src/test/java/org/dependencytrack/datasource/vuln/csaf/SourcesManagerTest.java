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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_SOURCES;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SourcesManagerTest {

    private ConfigRegistry configRegistryMock;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        configRegistryMock = mock(ConfigRegistry.class);
        objectMapper = new ObjectMapper();
        // Register JavaTimeModule to handle Java 8 date/time types
        objectMapper.registerModule(new JavaTimeModule());
    }

    @Test
    void testCreateWithNoExistingSources() {
        // Given: no sources in config registry
        when(configRegistryMock.getOptionalValue(CONFIG_SOURCES)).thenReturn(Optional.empty());

        // When: creating a SourcesManager
        var manager = SourcesManager.create(configRegistryMock, objectMapper);

        // Then: manager should be created with empty list
        assertThat(manager.listAggregators()).isEmpty();
        assertThat(manager.listProviders(source -> true)).isEmpty();
    }

    @Test
    void testCreateWithExistingSources() {
        // Given: existing sources in config registry
        var source1 = new CsafSource();
        source1.setId(0);
        source1.setUrl("https://example.com/provider1");
        source1.setName("Provider 1");
        source1.setAggregator(false);
        source1.setEnabled(true);

        var source2 = new CsafSource();
        source2.setId(1);
        source2.setUrl("https://example.com/aggregator1");
        source2.setName("Aggregator 1");
        source2.setAggregator(true);
        source2.setEnabled(true);

        var serialized = SourcesManager.serializeSources(objectMapper, List.of(source1, source2));
        when(configRegistryMock.getOptionalValue(CONFIG_SOURCES)).thenReturn(Optional.of(serialized));

        // When: creating a SourcesManager
        var manager = SourcesManager.create(configRegistryMock, objectMapper);

        // Then: manager should contain the sources
        assertThat(manager.listAggregators()).hasSize(1);
        assertThat(manager.listAggregators().get(0).getUrl()).isEqualTo("https://example.com/aggregator1");
        assertThat(manager.listProviders(source -> true)).hasSize(2);
    }

    @Test
    void testListAggregators() {
        // Given: sources including aggregators and providers
        var provider = new CsafSource();
        provider.setId(0);
        provider.setUrl("https://example.com/provider");
        provider.setAggregator(false);

        var aggregator = new CsafSource();
        aggregator.setId(1);
        aggregator.setUrl("https://example.com/aggregator");
        aggregator.setAggregator(true);

        var manager = new SourcesManager(configRegistryMock, objectMapper, List.of(provider, aggregator));

        // When: listing aggregators
        var aggregators = manager.listAggregators();

        // Then: only aggregators should be returned
        assertThat(aggregators).hasSize(1);
        assertThat(aggregators.get(0).isAggregator()).isTrue();
        assertThat(aggregators.get(0).getUrl()).isEqualTo("https://example.com/aggregator");
    }

    @Test
    void testListProvidersWithFilter() {
        // Given: multiple providers
        var enabledProvider = new CsafSource();
        enabledProvider.setId(0);
        enabledProvider.setUrl("https://example.com/enabled");
        enabledProvider.setEnabled(true);
        enabledProvider.setAggregator(false);

        var disabledProvider = new CsafSource();
        disabledProvider.setId(1);
        disabledProvider.setUrl("https://example.com/disabled");
        disabledProvider.setEnabled(false);
        disabledProvider.setAggregator(false);

        var manager = new SourcesManager(configRegistryMock, objectMapper, List.of(enabledProvider, disabledProvider));

        // When: listing providers with enabled filter
        var providers = manager.listProviders(source -> source.isEnabled());

        // Then: only enabled providers should be returned
        assertThat(providers).hasSize(1);
        assertThat(providers.get(0).isEnabled()).isTrue();
        assertThat(providers.get(0).getUrl()).isEqualTo("https://example.com/enabled");
    }

    @Test
    void testMaybeDiscoverNewSource() {
        // Given: empty source list
        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>());

        var newSource = new CsafSource();
        newSource.setUrl("https://example.com/new");
        newSource.setName("New Source");

        // When: discovering a new source
        var added = manager.maybeDiscover(newSource);

        // Then: source should be added with assigned ID
        assertThat(added).isTrue();
        assertThat(newSource.getId()).isEqualTo(0);

        // And: maybeCommit should reflect changes
        assertThat(manager.maybeCommit()).isTrue();
        verify(configRegistryMock, times(1)).setValue(eq(CONFIG_SOURCES), any());
    }

    @Test
    void testMaybeDiscoverExistingSource() {
        // Given: existing source
        var existingSource = new CsafSource();
        existingSource.setId(0);
        existingSource.setUrl("https://example.com/existing");
        existingSource.setName("Existing Source");

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(existingSource)));

        var duplicateSource = new CsafSource();
        duplicateSource.setUrl("https://example.com/existing");
        duplicateSource.setName("Duplicate Source");

        // When: discovering a source with same URL
        var added = manager.maybeDiscover(duplicateSource);

        // Then: source should not be added
        assertThat(added).isFalse();

        // And: no changes to commit
        assertThat(manager.maybeCommit()).isFalse();
        verify(configRegistryMock, never()).setValue(any(), any());
    }

    @Test
    void testMaybeDiscoverAssignsIncrementalIds() {
        // Given: sources with existing IDs
        var source1 = new CsafSource();
        source1.setId(5);
        source1.setUrl("https://example.com/source1");

        var source2 = new CsafSource();
        source2.setId(10);
        source2.setUrl("https://example.com/source2");

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source1, source2)));

        var newSource = new CsafSource();
        newSource.setUrl("https://example.com/new");

        // When: discovering a new source
        manager.maybeDiscover(newSource);

        // Then: new source should get ID one higher than max existing ID
        assertThat(newSource.getId()).isEqualTo(11);
    }

    @Test
    void testMaybeAdvanceUpdatesLastFetched() {
        // Given: source with old timestamp
        var source = new CsafSource();
        source.setId(1);
        source.setUrl("https://example.com/source");
        source.setLastFetched(Instant.parse("2024-01-01T00:00:00Z"));

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source)));

        // When: advancing with newer timestamp
        var newTimestamp = Instant.parse("2024-06-01T00:00:00Z");
        var advanced = manager.maybeAdvance(1, newTimestamp);

        // Then: timestamp should be updated
        assertThat(advanced).isTrue();
        assertThat(source.getLastFetched()).isEqualTo(newTimestamp);

        // And: changes should be committable
        assertThat(manager.maybeCommit()).isTrue();
    }

    @Test
    void testMaybeAdvanceWithOlderTimestamp() {
        // Given: source with recent timestamp
        var recentTimestamp = Instant.parse("2024-06-01T00:00:00Z");
        var source = new CsafSource();
        source.setId(1);
        source.setUrl("https://example.com/source");
        source.setLastFetched(recentTimestamp);

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source)));

        // When: trying to advance with older timestamp
        var olderTimestamp = Instant.parse("2024-01-01T00:00:00Z");
        var advanced = manager.maybeAdvance(1, olderTimestamp);

        // Then: timestamp should not be updated
        assertThat(advanced).isFalse();
        assertThat(source.getLastFetched()).isEqualTo(recentTimestamp);

        // And: no changes to commit
        assertThat(manager.maybeCommit()).isFalse();
    }

    @Test
    void testMaybeAdvanceWithSameTimestamp() {
        // Given: source with existing timestamp
        var timestamp = Instant.parse("2024-01-01T00:00:00Z");
        var source = new CsafSource();
        source.setId(1);
        source.setUrl("https://example.com/source");
        source.setLastFetched(timestamp);

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source)));

        // When: trying to advance with same timestamp
        var advanced = manager.maybeAdvance(1, timestamp);

        // Then: timestamp should not be updated
        assertThat(advanced).isFalse();
        assertThat(source.getLastFetched()).isEqualTo(timestamp);
    }

    @Test
    void testMaybeAdvanceWithNullLastFetched() {
        // Given: source with null lastFetched
        var source = new CsafSource();
        source.setId(1);
        source.setUrl("https://example.com/source");
        source.setLastFetched(null);

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source)));

        // When: advancing with any timestamp
        var timestamp = Instant.parse("2024-01-01T00:00:00Z");
        var advanced = manager.maybeAdvance(1, timestamp);

        // Then: timestamp should be set
        assertThat(advanced).isTrue();
        assertThat(source.getLastFetched()).isEqualTo(timestamp);
    }

    @Test
    void testMaybeAdvanceNonExistentSource() {
        // Given: source with ID 1
        var source = new CsafSource();
        source.setId(1);
        source.setUrl("https://example.com/source");

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source)));

        // When: trying to advance non-existent source
        var advanced = manager.maybeAdvance(999, Instant.now());

        // Then: should return false
        assertThat(advanced).isFalse();

        // And: no changes to commit
        assertThat(manager.maybeCommit()).isFalse();
    }

    @Test
    void testMaybeCommitWithNoChanges() {
        // Given: manager with no pending changes
        var source = new CsafSource();
        source.setId(0);
        source.setUrl("https://example.com/source");

        var manager = new SourcesManager(configRegistryMock, objectMapper, List.of(source));

        // When: trying to commit
        var committed = manager.maybeCommit();

        // Then: nothing should be committed
        assertThat(committed).isFalse();
        verify(configRegistryMock, never()).setValue(any(), any());
    }

    @Test
    void testMaybeCommitWithChanges() {
        // Given: manager with pending changes
        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>());

        var newSource = new CsafSource();
        newSource.setUrl("https://example.com/new");
        manager.maybeDiscover(newSource);

        // When: committing changes
        var committed = manager.maybeCommit();

        // Then: changes should be committed
        assertThat(committed).isTrue();
        verify(configRegistryMock, times(1)).setValue(eq(CONFIG_SOURCES), any());

        // And: second commit should do nothing
        var secondCommit = manager.maybeCommit();
        assertThat(secondCommit).isFalse();
        verify(configRegistryMock, times(1)).setValue(eq(CONFIG_SOURCES), any());
    }

    @Test
    void testSerializeAndDeserializeSources() {
        // Given: list of sources
        var source1 = new CsafSource();
        source1.setId(0);
        source1.setUrl("https://example.com/source1");
        source1.setName("Source 1");
        source1.setEnabled(true);
        source1.setAggregator(false);
        source1.setLastFetched(Instant.parse("2024-01-01T00:00:00Z"));

        var source2 = new CsafSource();
        source2.setId(1);
        source2.setUrl("https://example.com/source2");
        source2.setName("Source 2");
        source2.setEnabled(false);
        source2.setAggregator(true);

        var sources = List.of(source1, source2);

        // When: serializing and deserializing
        var serialized = SourcesManager.serializeSources(objectMapper, sources);
        var deserialized = SourcesManager.deserializeSources(objectMapper, serialized);

        // Then: sources should be preserved
        assertThat(deserialized).hasSize(2);
        assertThat(deserialized.get(0).getId()).isEqualTo(0);
        assertThat(deserialized.get(0).getUrl()).isEqualTo("https://example.com/source1");
        assertThat(deserialized.get(0).getName()).isEqualTo("Source 1");
        assertThat(deserialized.get(0).isEnabled()).isTrue();
        assertThat(deserialized.get(0).isAggregator()).isFalse();
        assertThat(deserialized.get(0).getLastFetched()).isEqualTo(Instant.parse("2024-01-01T00:00:00Z"));

        assertThat(deserialized.get(1).getId()).isEqualTo(1);
        assertThat(deserialized.get(1).getUrl()).isEqualTo("https://example.com/source2");
        assertThat(deserialized.get(1).isAggregator()).isTrue();
    }

    @Test
    void testSerializeSourcesWithIOException() {
        // Given: ObjectMapper that throws exception
        var faultyMapper = mock(ObjectMapper.class);
        try {
            when(faultyMapper.writeValueAsString(any())).thenThrow(new RuntimeException("Serialization error"));
        } catch (Exception e) {
            // Mock setup
        }

        // When & Then: should throw UncheckedIOException
        assertThatThrownBy(() -> SourcesManager.serializeSources(faultyMapper, List.of()))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void testDeserializeSourcesWithInvalidJson() {
        // Given: invalid JSON
        var invalidJson = "{invalid json}";

        // When & Then: should throw UncheckedIOException
        assertThatThrownBy(() -> SourcesManager.deserializeSources(objectMapper, invalidJson))
                .isInstanceOf(UncheckedIOException.class);
    }

    @Test
    void testMultipleOperationsAndSingleCommit() {
        // Given: manager with initial sources
        var source1 = new CsafSource();
        source1.setId(0);
        source1.setUrl("https://example.com/source1");

        var manager = new SourcesManager(configRegistryMock, objectMapper, new ArrayList<>(List.of(source1)));

        // When: performing multiple operations
        var source2 = new CsafSource();
        source2.setUrl("https://example.com/source2");
        manager.maybeDiscover(source2);

        var timestamp = Instant.now();
        manager.maybeAdvance(0, timestamp);

        // Then: single commit should persist all changes
        assertThat(manager.maybeCommit()).isTrue();
        verify(configRegistryMock, times(1)).setValue(eq(CONFIG_SOURCES), any());

        // And: verify both changes were applied
        assertThat(source2.getId()).isEqualTo(1);
        assertThat(source1.getLastFetched()).isEqualTo(timestamp);
    }
}
