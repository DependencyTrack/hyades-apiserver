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

import com.fasterxml.uuid.Generators;
import com.github.luben.zstd.Zstd;
import org.bouncycastle.jcajce.provider.digest.Blake3.Blake3_256;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.storage.FileStorage.requireValidName;

final class LocalFileStorage implements FileStorage {

    static final String EXTENSION_NAME = "local";
    private static final String METADATA_KEY_BLAKE3_DIGEST = "blake3_digest";

    private final Path baseDirPath;
    private final int compressionThresholdBytes;
    private final int compressionLevel;

    LocalFileStorage(
            final Path baseDirPath,
            final int compressionThresholdBytes,
            final int compressionLevel) {
        this.baseDirPath = baseDirPath;
        this.compressionThresholdBytes = compressionThresholdBytes;
        this.compressionLevel = compressionLevel;
    }

    @Override
    public FileMetadata store(final String name, final byte[] content) throws IOException {
        requireValidName(name);
        requireNonNull(content, "content must not be null");

        // NB: Using UUIDv7 ensures that file names are sortable by creation time.
        // TODO: Consider supporting sub-directories, where the provided name could be foo/bar/baz.
        final UUID uuid = Generators.timeBasedEpochRandomGenerator().generate();
        final Path filePath = resolveFilePath("%s_%s".formatted(uuid, name));

        final byte[] maybeCompressedContent = content.length >= compressionThresholdBytes
                ? Zstd.compress(content, compressionLevel)
                : content;

        // TODO: Blake3 optionally supports a key. Could use that to authenticate files.
        final byte[] contentDigest = new Blake3_256().digest(maybeCompressedContent);

        try (final var fileOutputStream = Files.newOutputStream(filePath);
             final var bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
            bufferedOutputStream.write(maybeCompressedContent);
        }

        return FileMetadata.newBuilder()
                .setKey(baseDirPath.relativize(filePath).toString())
                .setStorageName(EXTENSION_NAME)
                .putStorageMetadata(METADATA_KEY_BLAKE3_DIGEST, HexFormat.of().formatHex(contentDigest))
                .build();
    }

    @Override
    public byte[] get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        if (!EXTENSION_NAME.equals(fileMetadata.getStorageName())) {
            throw new IllegalArgumentException("Unable to retrieve file from storage: " + fileMetadata.getStorageName());
        }

        final String expectedContentDigestHex = fileMetadata.getStorageMetadataMap().get(METADATA_KEY_BLAKE3_DIGEST);
        if (expectedContentDigestHex == null) {
            throw new IllegalArgumentException("File metadata does not contain " + METADATA_KEY_BLAKE3_DIGEST);
        }

        final Path filePath = resolveFilePath(fileMetadata.getKey());

        final byte[] maybeCompressedContent = Files.readAllBytes(filePath);

        final byte[] actualContentDigest = new Blake3_256().digest(maybeCompressedContent);
        final byte[] expectedContentDigest = HexFormat.of().parseHex(expectedContentDigestHex);

        if (!Arrays.equals(actualContentDigest, expectedContentDigest)) {
            throw new IOException("File digest mismatch: actual=%s, expected=%s".formatted(
                    HexFormat.of().formatHex(actualContentDigest), expectedContentDigestHex));
        }

        final long decompressedSize = Zstd.decompressedSize(maybeCompressedContent);
        if (Zstd.decompressedSize(maybeCompressedContent) <= 0) {
            return maybeCompressedContent; // Not compressed.
        }

        return Zstd.decompress(maybeCompressedContent, Math.toIntExact(decompressedSize));
    }

    @Override
    public boolean delete(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        if (!EXTENSION_NAME.equals(fileMetadata.getStorageName())) {
            throw new IllegalArgumentException("Unable to delete file from storage: " + fileMetadata.getStorageName());
        }

        final Path filePath = resolveFilePath(fileMetadata.getKey());
        return Files.deleteIfExists(filePath);
    }

    Path resolveFilePath(final String key) {
        final Path filePath = baseDirPath.resolve(key).normalize().toAbsolutePath();
        if (!filePath.startsWith(baseDirPath)) {
            throw new IllegalStateException("""
                    The provided key %s does not resolve to a path within the \
                    configured file storage base directory (%s)""".formatted(key, baseDirPath));
        }

        return filePath;
    }

}
