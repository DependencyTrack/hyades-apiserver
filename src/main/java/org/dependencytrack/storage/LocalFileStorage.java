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
import org.apache.commons.codec.digest.DigestUtils;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

public class LocalFileStorage implements FileStorage {

    static final String EXTENSION_NAME = "local";

    private final Path baseDirPath;

    LocalFileStorage(final Path baseDirPath) {
        this.baseDirPath = baseDirPath;
    }

    @Override
    public FileMetadata store(final String name, final byte[] content) throws IOException {
        requireNonNull(name, "name must not be null");
        requireNonNull(content, "content must not be null");

        final UUID uuid = Generators.timeBasedEpochRandomGenerator().generate();
        final Path filePath = baseDirPath.resolve("%s_%s".formatted(uuid, name)).toAbsolutePath();
        final String sha256 = DigestUtils.sha256Hex(content);

        try (final var fileOutputStream = Files.newOutputStream(filePath);
             final var bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
            bufferedOutputStream.write(content);
        }

        return new FileMetadata(baseDirPath.relativize(filePath).toString(), EXTENSION_NAME, sha256);
    }

    @Override
    public byte[] get(final String key) throws IOException {
        final Path filePath = resolveFilePath(key);
        return Files.readAllBytes(filePath);
    }

    @Override
    public boolean delete(final String key) throws IOException {
        final Path filePath = resolveFilePath(key);
        return Files.deleteIfExists(filePath);
    }

    private Path resolveFilePath(final String key) {
        requireNonNull(key, "key must not be null");

        final Path filePath = baseDirPath.resolve(key).normalize().toAbsolutePath();
        if (!filePath.startsWith(baseDirPath)) {
            throw new IllegalStateException("""
                    The provided key %s does not resolve to a path within the \
                    configured file storage base directory (%s)""".formatted(key, baseDirPath));
        }

        return filePath;
    }

}