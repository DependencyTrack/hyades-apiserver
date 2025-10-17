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
package org.dependencytrack.filestorage.local;

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;
import org.dependencytrack.plugin.api.filestorage.FileStorage;
import org.dependencytrack.plugin.api.filestorage.FileStorageFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @since 5.6.0
 */
final class LocalFileStorageFactory implements FileStorageFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorageFactory.class);

    static final ConfigDefinition<Path> CONFIG_DIRECTORY =
            new DeploymentConfigDefinition<>("directory", ConfigTypes.PATH, /* isRequired */ true);

    private Path directoryPath;

    @Override
    public String extensionName() {
        return LocalFileStorage.EXTENSION_NAME;
    }

    @Override
    public Class<? extends FileStorage> extensionClass() {
        return LocalFileStorage.class;
    }

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public void init(final ExtensionContext ctx) {
        directoryPath = ctx.configRegistry().getValue(CONFIG_DIRECTORY);

        // Legacy behavior: The default data directory is specified as ~/.dependency-track,
        // but ~ is not resolved by Java's file API. Manual substitution is required.
        if (directoryPath.toString().startsWith("~")) {
            final Path userHomePath = Path.of(System.getProperty("user.home"));
            directoryPath = Path.of(directoryPath.toString().replaceFirst(
                    "^~", userHomePath.toAbsolutePath().toString()));
        }
        directoryPath = directoryPath.normalize().toAbsolutePath();

        try {
            Files.createDirectories(directoryPath);
        } catch (IOException e) {
            throw new IllegalStateException("""
                    Failed to create directory for file storage at %s\
                    """.formatted(directoryPath), e);
        }

        final boolean canRead = directoryPath.toFile().canRead();
        final boolean canWrite = directoryPath.toFile().canWrite();
        if (!canRead || !canWrite) {
            throw new IllegalStateException(
                    "Insufficient permissions for directory %s (canRead=%s, canWrite=%s)".formatted(
                            directoryPath, canRead, canWrite));
        }

        LOGGER.debug("Files will be stored in {}", directoryPath);
    }

    @Override
    public FileStorage create() {
        return new LocalFileStorage(directoryPath);
    }

}
