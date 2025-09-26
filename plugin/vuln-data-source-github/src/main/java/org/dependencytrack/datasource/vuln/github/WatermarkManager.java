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
package org.dependencytrack.datasource.vuln.github;

import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_WATERMARK;

/**
 * @since 5.7.0
 */
final class WatermarkManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkManager.class);
    private static final Duration MIN_COMMIT_INTERVAL = Duration.ofSeconds(3);

    private final Clock clock;
    private final ConfigRegistry configRegistry;
    private Instant committedWatermark;
    private Instant pendingWatermark;
    private Instant lastCommittedAt;

    private WatermarkManager(
            final Clock clock,
            final ConfigRegistry configRegistry,
            final Instant committedWatermark) {
        this.clock = clock;
        this.configRegistry = configRegistry;
        this.committedWatermark = committedWatermark;
        this.pendingWatermark = committedWatermark;
        this.lastCommittedAt = Instant.now(clock);
    }

    static WatermarkManager create(final Clock clock, final ConfigRegistry configRegistry) {
        requireNonNull(clock, "clock must not be null");
        requireNonNull(configRegistry, "configRegistry must not be null");

        final Instant committedWatermark =
                configRegistry.getOptionalValue(CONFIG_WATERMARK).orElse(null);
        return new WatermarkManager(clock, configRegistry, committedWatermark);
    }

    Instant getWatermark() {
        return committedWatermark;
    }

    void maybeAdvance(final Instant watermark) {
        if (watermark == null) {
            return;
        }
        if (pendingWatermark == null || pendingWatermark.isBefore(watermark)) {
            LOGGER.debug("Advancing watermark from {} to {}", pendingWatermark, watermark);
            pendingWatermark = watermark;
        }
    }

    void maybeCommit(final boolean ignoreMinCommitInterval) {
        if (pendingWatermark == null
                || (committedWatermark != null && committedWatermark.equals(pendingWatermark))) {
            return;
        }
        if (!ignoreMinCommitInterval
                && Duration.between(lastCommittedAt, Instant.now(clock)).compareTo(MIN_COMMIT_INTERVAL) < 0) {
            return;
        }

        LOGGER.debug("Committing watermark {}", pendingWatermark);
        configRegistry.setValue(CONFIG_WATERMARK, pendingWatermark);
        committedWatermark = pendingWatermark;
        lastCommittedAt = Instant.now(clock);
    }

}
