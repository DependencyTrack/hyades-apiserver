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
package org.dependencytrack.vulndatasource.nvd;

import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.ExtensionKVStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * @since 5.7.0
 */
final class WatermarkManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkManager.class);

    private final ExtensionKVStore kvStore;
    private Instant committedWatermark;
    private Instant pendingWatermark;
    private Long committedWatermarkVersion;

    private WatermarkManager(
            final ExtensionKVStore kvStore,
            final Instant committedWatermark,
            final Long committedWatermarkVersion) {
        this.kvStore = kvStore;
        this.committedWatermark = committedWatermark;
        this.committedWatermarkVersion = committedWatermarkVersion;
    }

    // TODO: Just use constructor after upgrading to Java 25: https://openjdk.org/jeps/513
    static WatermarkManager create(final ExtensionKVStore kvStore) {
        final ExtensionKVStore.Entry watermarkEntry = kvStore.get("watermark");
        if (watermarkEntry != null) {
            try {
                final Instant committedWatermark = Instant.ofEpochMilli(
                        Long.parseLong(watermarkEntry.value()));
                return new WatermarkManager(kvStore, committedWatermark, watermarkEntry.version());
            } catch (NumberFormatException ex) {
                LOGGER.warn("Encountered invalid watermark: {}; Ignoring", watermarkEntry, ex);
            }
        }

        return new WatermarkManager(kvStore, null, null);
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

    void maybeCommit() {
        if (pendingWatermark == null
                || (committedWatermark != null && committedWatermark.equals(pendingWatermark))) {
            return;
        }

        LOGGER.debug("Committing watermark {} to KV store", pendingWatermark);
        final CompareAndPutResult capResult = kvStore.compareAndPut(
                "watermark",
                String.valueOf(pendingWatermark.toEpochMilli()),
                committedWatermarkVersion);
        switch (capResult) {
            case CompareAndPutResult.Success(long newVersion) -> {
                committedWatermark = pendingWatermark;
                committedWatermarkVersion = newVersion;
                pendingWatermark = null;
            }
            case CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason reason) ->
                    throw new IllegalStateException(
                            "Failed to commit watermark %s to KV store: %s".formatted(
                                    pendingWatermark, reason));
        }
    }

}
