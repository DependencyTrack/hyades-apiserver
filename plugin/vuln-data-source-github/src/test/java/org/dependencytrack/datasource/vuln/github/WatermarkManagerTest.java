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

import org.dependencytrack.plugin.api.config.MockConfigRegistry;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.datasource.vuln.github.GitHubVulnDataSourceConfigs.CONFIG_WATERMARK;

class WatermarkManagerTest {

    @Test
    void createShouldInitializeWatermarkWhenAvailable() {
        final var watermark = Instant.ofEpochSecond(666);

        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_WATERMARK, watermark);

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), configRegistry);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermark()).isEqualTo(watermark);
    }

    @Test
    void createShouldNotInitializeWatermarkWhenNotAvailable() {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_WATERMARK, null);

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), configRegistry);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermark()).isNull();
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsNull() {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_WATERMARK, null);

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), configRegistry);

        watermarkManager.maybeAdvance(Instant.ofEpochSecond(666));
        assertThat(watermarkManager.getWatermark()).isNull();

        watermarkManager.maybeCommit(true);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(666));
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsEarlier() {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_WATERMARK, Instant.ofEpochSecond(666));

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), configRegistry);

        watermarkManager.maybeAdvance(Instant.ofEpochSecond(667));
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(666));

        watermarkManager.maybeCommit(true);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(667));
    }

    @Test
    void maybeCommitShouldNotCommitWhenLastCommitWasLessThanThreeSecondsBack() {
        final var configRegistry = new MockConfigRegistry();
        configRegistry.setValue(CONFIG_WATERMARK, Instant.ofEpochSecond(111));

        final var clock = new MutableClock(Instant.ofEpochSecond(666));
        final var watermarkManager = WatermarkManager.create(clock, configRegistry);

        watermarkManager.maybeAdvance(Instant.ofEpochSecond(222));
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(111));

        watermarkManager.maybeCommit(false);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(111));

        clock.advance(Duration.ofSeconds(3));
        watermarkManager.maybeCommit(false);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(222));
    }

    private static class MutableClock extends Clock {

        private Instant currentInstant;

        private MutableClock(final Instant initialInstant) {
            this.currentInstant = initialInstant;
        }

        private void advance(final Duration duration) {
            currentInstant = currentInstant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return Clock.systemUTC().getZone();
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant instant() {
            return currentInstant;
        }

    }

}