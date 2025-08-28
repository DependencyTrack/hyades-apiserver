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
package org.dependencytrack.filestorage;

import alpine.Config;
import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
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
public final class LocalFileStorageFactory implements FileStorageFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorageFactory.class);

    static final ConfigDefinition<Path> CONFIG_DIRECTORY =
            new DeploymentConfigDefinition<>("directory", ConfigTypes.PATH, /* isRequired */ false);
    static final ConfigDefinition<Integer> CONFIG_COMPRESSION_THRESHOLD_BYTES =
            new DeploymentConfigDefinition<>("compression.threshold.bytes", ConfigTypes.INTEGER, /* isRequired */ false);
    static final ConfigDefinition<Integer> CONFIG_COMPRESSION_LEVEL =
            new DeploymentConfigDefinition<>("compression.level", ConfigTypes.INTEGER, /* isRequired */ false);

    private Path directoryPath;
    private int compressionThresholdBytes;
    private int compressionLevel;

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
    public void init(final ConfigRegistry configRegistry) {
        directoryPath = configRegistry.getOptionalValue(CONFIG_DIRECTORY)
                .orElseGet(() -> Config.getInstance().getDataDirectorty().toPath().resolve("storage"))
                .normalize()
                .toAbsolutePath();

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

        compressionThresholdBytes = configRegistry.getOptionalValue(CONFIG_COMPRESSION_THRESHOLD_BYTES).orElse(4096);
        compressionLevel = configRegistry.getOptionalValue(CONFIG_COMPRESSION_LEVEL).orElse(5);
    }

    @Override
    public FileStorage create() {
        return new LocalFileStorage(directoryPath, compressionThresholdBytes, compressionLevel);
    }

}
