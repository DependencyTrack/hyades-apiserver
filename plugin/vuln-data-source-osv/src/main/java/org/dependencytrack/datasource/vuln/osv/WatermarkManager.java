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
package org.dependencytrack.datasource.vuln.osv;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.dependencytrack.datasource.vuln.osv.OsvVulnDataSourceConfigs.CONFIG_WATERMARKS;

/**
 * @since 5.7.0
 */
final class WatermarkManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkManager.class);

    private final ConfigRegistry configRegistry;
    private final ObjectMapper objectMapper;
    private final Map<String, Instant> pendingWatermarkByEcosystem;
    private final Map<String, Instant> committedWatermarkByEcosystem;

    private WatermarkManager(
            final ConfigRegistry configRegistry,
            final ObjectMapper objectMapper,
            final Map<String, Instant> committedWatermarkByEcosystem) {
        this.configRegistry = configRegistry;
        this.objectMapper = objectMapper;
        this.pendingWatermarkByEcosystem = new HashMap<>();
        this.committedWatermarkByEcosystem = committedWatermarkByEcosystem;
    }

    // TODO: Just use constructor after upgrading to Java 25 (https://openjdk.org/jeps/513)
    static WatermarkManager create(
            final ConfigRegistry configRegistry,
            final ObjectMapper objectMapper) {
        final Map<String, Instant> watermarkByEcosystem =
                configRegistry.getOptionalValue(CONFIG_WATERMARKS)
                        .map(value -> deserializeWatermarks(objectMapper, value))
                        .orElseGet(HashMap::new);

        return new WatermarkManager(configRegistry, objectMapper, watermarkByEcosystem);
    }

    Instant getWatermark(final String ecosystem) {
        return committedWatermarkByEcosystem.get(ecosystem);
    }

    long getWatermarksCount() {
        return configRegistry.getOptionalValue(CONFIG_WATERMARKS)
                .map(value -> deserializeWatermarks(objectMapper, value).size())
                .orElse(0);
    }

    void maybeAdvance(final String ecosystem, final Instant watermark) {
        pendingWatermarkByEcosystem.compute(ecosystem, (ignored, oldWatermark) -> {
            if (oldWatermark != null && oldWatermark.isAfter(watermark)) {
                return oldWatermark;
            }

            return watermark;
        });
    }

    void maybeCommit(final Collection<String> ecosystems) {
        final var watermarksToCommit = new HashMap<>(committedWatermarkByEcosystem);
        for (final Map.Entry<String, Instant> entry : pendingWatermarkByEcosystem.entrySet()) {
            final String ecosystem = entry.getKey();
            if (!ecosystems.contains(ecosystem)) {
                continue;
            }

            final Instant watermark = entry.getValue();

            watermarksToCommit.compute(ecosystem, (ignored, oldWatermark) -> {
                if (oldWatermark != null && oldWatermark.isAfter(watermark)) {
                    return oldWatermark;
                }

                return watermark;
            });
        }

        if (watermarksToCommit.equals(committedWatermarkByEcosystem)) {
            LOGGER.debug("Watermarks didn't change; Nothing to commit");
            return;
        }

        LOGGER.debug("Committing watermarks: {}", watermarksToCommit);
        final String serializedWatermarks = serializeWatermarks(watermarksToCommit);
        configRegistry.setValue(CONFIG_WATERMARKS, serializedWatermarks);
        pendingWatermarkByEcosystem.clear();
        committedWatermarkByEcosystem.clear();
        committedWatermarkByEcosystem.putAll(watermarksToCommit);
    }

    private static Map<String, Instant> deserializeWatermarks(
            final ObjectMapper objectMapper,
            final String serializedWatermarks) {
        try {
            return objectMapper.readValue(serializedWatermarks, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String serializeWatermarks(final Map<String, Instant> watermarks) {
        try {
            return objectMapper.writeValueAsString(watermarks);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}