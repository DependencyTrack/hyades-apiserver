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
import alpine.common.logging.Logger;
import org.dependencytrack.plugin.api.ConfigDefinition;
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ConfigSource;
import org.dependencytrack.plugin.api.ExtensionFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @since 5.6.0
 */
public class LocalBomUploadStorageFactory implements ExtensionFactory<BomUploadStorage> {

    private static final Logger LOGGER = Logger.getLogger(LocalBomUploadStorageFactory.class);

    private static final ConfigDefinition CONFIG_DIRECTORY = new ConfigDefinition(
            "directory",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);

    private Path directoryPath;

    @Override
    public String extensionName() {
        return LocalBomUploadStorage.EXTENSION_NAME;
    }

    @Override
    public Class<? extends BomUploadStorage> extensionClass() {
        return LocalBomUploadStorage.class;
    }

    @Override
    public int priority() {
        return 110;
    }

    @Override
    public void init(final ConfigRegistry configRegistry) {
        directoryPath = configRegistry.getOptionalValue(CONFIG_DIRECTORY)
                .map(Paths::get)
                .orElseGet(() -> {
                    final Path path = Config.getInstance().getDataDirectorty().toPath().resolve("bom-uploads");
                    try {
                        return Files.createDirectories(path);
                    } catch (IOException e) {
                        throw new IllegalStateException("""
                                Failed to create directory for BOM upload storage at %s\
                                """.formatted(path), e);
                    }
                });

        final boolean canRead = directoryPath.toFile().canRead();
        final boolean canWrite = directoryPath.toFile().canWrite();
        if (!canRead || !canWrite) {
            throw new IllegalStateException("Insufficient permissions for directory %s (canRead=%s, canWrite=%s)"
                    .formatted(directoryPath, canRead, canWrite));
        }

        LOGGER.info("BOM uploads will be stored in %s".formatted(directoryPath));
    }

    @Override
    public BomUploadStorage create() {
        return new LocalBomUploadStorage(directoryPath);
    }

}
