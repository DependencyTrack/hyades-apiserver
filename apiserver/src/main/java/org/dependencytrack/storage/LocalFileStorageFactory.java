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

import alpine.Config;
import org.dependencytrack.plugin.api.ConfigDefinition;
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ConfigSource;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @since 5.6.0
 */
public final class LocalFileStorageFactory implements ExtensionFactory<FileStorage> {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorageFactory.class);

    static final ConfigDefinition CONFIG_DIRECTORY = new ConfigDefinition(
            "directory",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);
    static final ConfigDefinition CONFIG_COMPRESSION_THRESHOLD_BYTES = new ConfigDefinition(
            "compression.threshold.bytes",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);
    static final ConfigDefinition CONFIG_COMPRESSION_LEVEL = new ConfigDefinition(
            "compression.level",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);

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
                .map(Paths::get)
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

        compressionThresholdBytes = configRegistry.getOptionalValue(CONFIG_COMPRESSION_THRESHOLD_BYTES)
                .map(Integer::parseInt)
                .orElse(4096);
        compressionLevel = configRegistry.getOptionalValue(CONFIG_COMPRESSION_LEVEL)
                .map(Integer::parseInt)
                .orElse(5);
    }

    @Override
    public FileStorage create() {
        return new LocalFileStorage(directoryPath, compressionThresholdBytes, compressionLevel);
    }

}
