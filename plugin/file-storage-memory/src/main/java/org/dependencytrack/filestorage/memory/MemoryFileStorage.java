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
package org.dependencytrack.filestorage.memory;

import org.dependencytrack.plugin.api.filestorage.FileStorage;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.plugin.api.filestorage.FileStorage.requireValidFileName;

/**
 * @since 5.6.0
 */
final class MemoryFileStorage implements FileStorage {

    static final String EXTENSION_NAME = "memory";

    private final Map<String, byte[]> fileContentByKey;

    MemoryFileStorage(final Map<String, byte[]> fileContentByKey) {
        this.fileContentByKey = requireNonNull(fileContentByKey);
    }

    @Override
    public FileMetadata store(final String fileName, final String mediaType, final InputStream contentStream) throws IOException {
        requireValidFileName(fileName);
        requireNonNull(contentStream, "contentStream must not be null");

        final String normalizedFileName = normalizeFileName(fileName);
        final URI locationUri = URI.create(EXTENSION_NAME + ":///" + normalizedFileName);

        final MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        final var byteArrayOutputStream = new ByteArrayOutputStream();
        try (final var digestOutputStream = new DigestOutputStream(byteArrayOutputStream, messageDigest)) {
            contentStream.transferTo(digestOutputStream);
        }

        fileContentByKey.put(fileName, byteArrayOutputStream.toByteArray());

        return FileMetadata.newBuilder()
                .setLocation(locationUri.toString())
                .setMediaType(mediaType)
                .setSha256Digest(HexFormat.of().formatHex(messageDigest.digest()))
                .build();
    }

    @Override
    public InputStream get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final String fileName = resolveFileName(fileMetadata);

        final byte[] fileContent = fileContentByKey.get(fileName);
        if (fileContent == null) {
            throw new NoSuchFileException(fileMetadata.getLocation());
        }

        return new ByteArrayInputStream(fileContent);
    }

    @Override
    public boolean delete(final FileMetadata fileMetadata) {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final String filePath = resolveFileName(fileMetadata);

        return fileContentByKey.remove(filePath) != null;
    }

    private static String normalizeFileName(final String fileName) {
        return Paths.get(fileName).normalize().toString();
    }

    private static String resolveFileName(final FileMetadata fileMetadata) {
        final URI locationUri = URI.create(fileMetadata.getLocation());
        if (!EXTENSION_NAME.equals(locationUri.getScheme())) {
            throw new IllegalArgumentException("%s: Unexpected scheme %s, expected %s".formatted(
                    locationUri, locationUri.getScheme(), EXTENSION_NAME));
        }
        if (locationUri.getHost() != null) {
            throw new IllegalArgumentException(
                    "%s: Host portion is not allowed for scheme %s".formatted(locationUri, EXTENSION_NAME));
        }
        if (locationUri.getPath() == null) {
            throw new IllegalArgumentException(
                    "%s: Path portion not set; Unable to determine file name".formatted(locationUri));
        }

        // The value returned by URI#getPath always has a leading slash.
        // Remove it to prevent the path from erroneously be interpreted as absolute.
        return normalizeFileName(locationUri.getPath().replaceFirst("^/", ""));
    }

}
