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

import alpine.common.logging.Logger;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * A {@link BomUploadStorage} that stores uploaded BOMs on the local filesystem.
 *
 * @since 5.6.0
 */
class LocalBomUploadStorage implements BomUploadStorage {

    private static final Logger LOGGER = Logger.getLogger(LocalBomUploadStorage.class);
    static final String EXTENSION_NAME = "local";

    private final Path baseDirPath;

    LocalBomUploadStorage(final Path baseDirPath) {
        this.baseDirPath = baseDirPath;
    }

    @Override
    public void storeBom(final UUID token, final byte[] bom) throws IOException {
        final Path outputFilePath = baseDirPath.resolve(token.toString());
        LOGGER.debug("Storing BOM at %s".formatted(outputFilePath));

        try (final var fileOutputStream = Files.newOutputStream(outputFilePath);
             final var bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
            bufferedOutputStream.write(bom);
        }
    }

    @Override
    public byte[] getBomByToken(final UUID token) throws IOException {
        final Path inputFilePath = baseDirPath.resolve(token.toString());
        LOGGER.debug("Retrieving BOM from %s".formatted(inputFilePath));

        try {
            return Files.readAllBytes(inputFilePath);
        } catch (NoSuchFileException e) {
            return null;
        }
    }

    @Override
    public boolean deleteBomByToken(final UUID token) throws IOException {
        final Path bomFilePath = baseDirPath.resolve(token.toString());
        LOGGER.debug("Deleting BOM from %s".formatted(token));

        return Files.deleteIfExists(bomFilePath);
    }

    @Override
    public int deleteBomsForRetentionDuration(final Duration duration) throws IOException {
        final File[] bomFiles = baseDirPath.toFile().listFiles();
        if (bomFiles == null || bomFiles.length == 0) {
            return 0;
        }

        final Instant retentionCutoff = Instant.now().minus(duration);

        int bomFilesDeleted = 0;
        for (final File file : bomFiles) {
            final Path filePath = file.toPath();

            // TODO: Is this reliable for all filesystems?
            // TODO: Is this problematic for network volumes in other timezones?
            final var attributes = Files.readAttributes(filePath, BasicFileAttributes.class);
            if (retentionCutoff.isAfter(attributes.lastModifiedTime().toInstant())) {
                LOGGER.debug("Deleting BOM from %s".formatted(filePath));
                Files.delete(filePath);
                bomFilesDeleted++;
            }
        }

        return bomFilesDeleted;
    }

}
