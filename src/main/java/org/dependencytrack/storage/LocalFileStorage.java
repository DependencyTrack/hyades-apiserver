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
import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.storage.FileStorage.requireValidFileName;

/**
 * @since 5.6.0
 */
final class LocalFileStorage implements FileStorage {

    static final String EXTENSION_NAME = "local";
    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorage.class);

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
    public FileMetadata store(final String fileName, final String mediaType, final byte[] content) throws IOException {
        requireValidFileName(fileName);
        requireNonNull(content, "content must not be null");

        final Path filePath = resolveFilePath(fileName);
        if (Files.isDirectory(filePath)) {
            throw new IOException("Path %s exists, but is a directory".formatted(fileName));
        }
        if (!Files.exists(filePath.getParent())) {
            LOGGER.debug("Creating parent directories of {}", filePath);
            Files.createDirectories(filePath.getParent());
        }

        final Path relativeFilePath = baseDirPath.relativize(filePath);

        final URI locationUri;
        try {
            locationUri = new URIBuilder()
                    .setScheme(EXTENSION_NAME)
                    .setHost("")
                    .setPath(relativeFilePath.toString())
                    .build();
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Failed to build URI for " + relativeFilePath, e);
        }

        final byte[] maybeCompressedContent = content.length >= compressionThresholdBytes
                ? Zstd.compress(content, compressionLevel)
                : content;

        final byte[] contentDigest = DigestUtils.sha256(maybeCompressedContent);

        try (final var fileOutputStream = Files.newOutputStream(filePath);
             final var bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
            bufferedOutputStream.write(maybeCompressedContent);
        }

        return FileMetadata.newBuilder()
                .setLocation(locationUri.toString())
                .setMediaType(mediaType)
                .setSha256Digest(HexFormat.of().formatHex(contentDigest))
                .build();
    }

    @Override
    public byte[] get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final Path filePath = resolveFilePath(fileMetadata);

        final byte[] maybeCompressedContent = Files.readAllBytes(filePath);
        final byte[] actualContentDigest = DigestUtils.sha256(maybeCompressedContent);
        final byte[] expectedContentDigest = HexFormat.of().parseHex(fileMetadata.getSha256Digest());

        if (!Arrays.equals(actualContentDigest, expectedContentDigest)) {
            throw new IOException("SHA256 digest mismatch: actual=%s, expected=%s".formatted(
                    HexFormat.of().formatHex(actualContentDigest), fileMetadata.getSha256Digest()));
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

        final Path filePath = resolveFilePath(fileMetadata);

        return Files.deleteIfExists(filePath);
    }

    private Path resolveFilePath(final String filePath) {
        final Path resolvedFilePath = baseDirPath.resolve(filePath).normalize().toAbsolutePath();
        if (!resolvedFilePath.startsWith(baseDirPath)) {
            throw new IllegalArgumentException("""
                    The provided filePath %s does not resolve to a path within the \
                    configured base directory (%s)""".formatted(filePath, baseDirPath));
        }

        return resolvedFilePath;
    }

    @VisibleForTesting
    Path resolveFilePath(final FileMetadata fileMetadata) {
        final URI locationUri = URI.create(fileMetadata.getLocation());
        if (!EXTENSION_NAME.equals(locationUri.getScheme())) {
            throw new IllegalArgumentException("%s: Unexpected scheme %s, expected %s".formatted(
                    locationUri, locationUri.getScheme(), EXTENSION_NAME));
        }
        if (locationUri.getHost() != null) {
            throw new IllegalArgumentException(
                    "%s: Host portion is not allowed for scheme %s".formatted(locationUri, EXTENSION_NAME));
        }
        if (locationUri.getPath() == null || locationUri.getPath().equals("/")) {
            throw new IllegalArgumentException(
                    "%s: Path portion not set; Unable to determine file name".formatted(locationUri));
        }

        // The value returned by URI#getPath always has a leading slash.
        // Remove it to prevent the path from erroneously be interpreted as absolute.
        return resolveFilePath(locationUri.getPath().replaceFirst("^/", ""));
    }

}
