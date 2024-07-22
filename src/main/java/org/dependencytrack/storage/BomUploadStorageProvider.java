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
package org.dependencytrack.storage;

import com.github.luben.zstd.Zstd;

import java.io.IOException;
import java.time.Duration;
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.UUID;

/**
 * @since 5.6.0
 */
public interface BomUploadStorageProvider {

    void storeBom(final UUID token, final byte[] bom) throws IOException;

    byte[] getBomByToken(final UUID token) throws IOException;

    boolean deleteBomByToken(final UUID token) throws IOException;

    int deleteBomsForRetentionDuration(final Duration duration) throws IOException;

    default void storeBomCompressed(final UUID token, final byte[] bom, final int compressionLevel) throws IOException {
        final byte[] compressedBom = Zstd.compress(bom, compressionLevel);
        storeBom(token, compressedBom);
    }

    default byte[] getDecompressedBomByToken(final UUID token) throws IOException {
        final byte[] compressedBom = getBomByToken(token);
        if (compressedBom == null) {
            return null;
        }

        final long decompressedSize = Zstd.decompressedSize(compressedBom);
        if (decompressedSize <= 0) {
            return compressedBom; // Not compressed.
        }

        return Zstd.decompress(compressedBom, (int) decompressedSize);
    }

    static BomUploadStorageProvider getForClassName(final String providerClassName) {
        final var serviceLoader = ServiceLoader.load(BomUploadStorageProvider.class);
        return serviceLoader.stream()
                .filter(provider -> provider.type().getName().equals(providerClassName))
                .findFirst()
                .map(ServiceLoader.Provider::get)
                .orElseThrow(() -> new NoSuchElementException("%s is not a known storage provider".formatted(providerClassName)));
    }

    static boolean exists(final String providerClassName) {
        final var serviceLoader = ServiceLoader.load(BomUploadStorageProvider.class);
        return serviceLoader.stream().anyMatch(provider -> provider.type().getName().equals(providerClassName));
    }

}
