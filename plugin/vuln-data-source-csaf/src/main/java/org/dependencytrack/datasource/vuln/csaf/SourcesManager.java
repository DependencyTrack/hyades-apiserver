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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import static org.dependencytrack.datasource.vuln.csaf.CsafVulnDataSourceConfigs.CONFIG_SOURCES;

/**
 * Manages CSAF sources, including reading from and writing to the config registry as well as writing a watermark when a
 * source was last fetched.
 *
 * @since 5.7.0
 */
public class SourcesManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(SourcesManager.class);

    private final ConfigRegistry configRegistry;
    private final ObjectMapper objectMapper;
    private final List<CsafSource> commitedSources;
    private final List<CsafSource> pendingSources;
    private Boolean isDirty = false;

    public SourcesManager(
            ConfigRegistry configRegistry,
            ObjectMapper objectMapper,
            List<CsafSource> commitedSources) {
        this.configRegistry = configRegistry;
        this.objectMapper = objectMapper;
        this.commitedSources = commitedSources;
        this.pendingSources = new ArrayList<>(commitedSources);
    }

    static SourcesManager create(
            final ConfigRegistry configRegistry,
            final ObjectMapper objectMapper) {

        var sources  = configRegistry.getOptionalValue(CONFIG_SOURCES)
                .map(value -> deserializeSources(objectMapper, value))
                .orElse(new ArrayList<>());

        return new SourcesManager(configRegistry, objectMapper, sources);
    }

    public List<CsafSource> listAggregators() {
        return this.commitedSources.stream().filter(CsafSource::isAggregator).toList();
    }

    public List<CsafSource> listProviders(Predicate<CsafSource> filter) {
        return this.commitedSources.stream().filter(filter).toList();
    }

    /**
     * Add the given source if it does not already exist (based on URL).
     * This does not yet commit this source into the config registry.
     *
     * @param source the source to maybe add
     * @return true if the source was added, false if it already existed
     */
    public boolean maybeDiscover(final CsafSource source) {
        if (this.pendingSources.stream().noneMatch(s -> s.getUrl().equals(source.getUrl()))) {
            source.setId(this.pendingSources.size());
            this.pendingSources.add(source);
            this.isDirty = true;
            return true;
        }

        return false;
    }

    /**
     * Advance the lastFetched timestamp of the source with the given id if it exists.
     * This does not yet commit this change into the config registry.
     *
     * @param id          the id of the source to maybe advance
     * @param lastFetched the new lastFetched timestamp
     * @return true if the source was advanced, false if it does not exist, or the new timestamp is not after the current one
     */
    public boolean maybeAdvance(int id, Instant lastFetched) {
        for (var source : this.pendingSources) {
            if (source.getId() == id) {
                if (source.getLastFetched() != null && !source.getLastFetched().isBefore(lastFetched)) {
                    return false;
                }

                source.setLastFetched(lastFetched);
                this.isDirty = true;
                return true;
            }
        }
        return false;
    }

    /**
     * If there are pending changes, commit them to the config registry.
     *
     * @return true if changes were committed, false if there were no changes to commit
     */
    public boolean maybeCommit() {
        if (!this.isDirty) {
            return false;
        }

        this.configRegistry.setValue(CONFIG_SOURCES, serializeSources(this.objectMapper, this.pendingSources));
        this.isDirty = false;

        LOGGER.info("Committed {} CSAF sources", this.pendingSources.size());
        return true;
    }

    public static String serializeSources(
            final ObjectMapper objectMapper,
            final List<CsafSource> sources) {
        try {
            return objectMapper.writeValueAsString(sources);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static List<CsafSource> deserializeSources(
            final ObjectMapper objectMapper,
            final String serializedSources) {
        try {
            return objectMapper.readValue(serializedSources, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
