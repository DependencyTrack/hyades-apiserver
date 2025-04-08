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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.storage.FileStorage.requireValidFileName;

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
    public FileMetadata store(final String fileName, final String mediaType, final byte[] content) {
        requireValidFileName(fileName);
        requireNonNull(content, "content must not be null");

        final String normalizedFileName = normalizeFileName(fileName);

        final URI locationUri;
        try {
            locationUri = new URIBuilder()
                    .setScheme(EXTENSION_NAME)
                    .setHost("")
                    .setPath(normalizedFileName)
                    .build();
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Failed to build URI for " + fileName, e);
        }

        final byte[] contentDigest = DigestUtils.sha256(content);

        fileContentByKey.put(fileName, content);

        return FileMetadata.newBuilder()
                .setLocation(locationUri.toString())
                .setMediaType(mediaType)
                .setSha256Digest(HexFormat.of().formatHex(contentDigest))
                .build();
    }

    @Override
    public byte[] get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final String fileName = resolveFileName(fileMetadata);

        final byte[] fileContent = fileContentByKey.get(fileName);
        if (fileContent == null) {
            throw new NoSuchFileException(fileMetadata.getLocation());
        }

        final byte[] actualContentDigest = DigestUtils.sha256(fileContent);
        final byte[] expectedContentDigest = HexFormat.of().parseHex(fileMetadata.getSha256Digest());

        if (!Arrays.equals(actualContentDigest, expectedContentDigest)) {
            throw new IOException("SHA256 digest mismatch: actual=%s, expected=%s".formatted(
                    HexFormat.of().formatHex(actualContentDigest), fileMetadata.getSha256Digest()));
        }

        return fileContent;
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
