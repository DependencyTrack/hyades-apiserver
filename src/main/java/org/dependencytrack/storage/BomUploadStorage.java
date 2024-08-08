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
import org.dependencytrack.plugin.api.ExtensionPoint;

import java.io.IOException;
import java.time.Duration;
import java.util.UUID;

/**
 * @since 5.6.0
 */
public interface BomUploadStorage extends ExtensionPoint {

    /**
     * @param token The token to store the BOM for.
     * @param bom   The BOM to store.
     * @throws IOException When storing the BOM failed.
     */
    void storeBom(final UUID token, final byte[] bom) throws IOException;

    /**
     * @param token The token to get the BOM for.
     * @return The BOM, or {@code null} when no BOM was found.
     * @throws IOException When getting the BOM failed.
     */
    byte[] getBomByToken(final UUID token) throws IOException;

    /**
     * @param token The token to delete the BOM for.
     * @return {@code true} when the BOM was deleted, otherwise {@code false}.
     * @throws IOException When deleting the BOM failed.
     */
    boolean deleteBomByToken(final UUID token) throws IOException;

    int deleteBomsForRetentionDuration(final Duration duration) throws IOException;

    /**
     * @param token            The token to store the BOM for.
     * @param bom              The BOM to store.
     * @param compressionLevel The compression level to use.
     * @throws IOException When storing the BOM failed.
     * @see #storeBom(UUID, byte[])
     */
    default void storeBomCompressed(final UUID token, final byte[] bom, final int compressionLevel) throws IOException {
        final byte[] compressedBom = Zstd.compress(bom, compressionLevel);
        storeBom(token, compressedBom);
    }

    /**
     * @param token The token to get the BOM for.
     * @return The BOM, or {@code null} when no BOM was found.
     * @throws IOException When getting the BOM failed.
     */
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

}
