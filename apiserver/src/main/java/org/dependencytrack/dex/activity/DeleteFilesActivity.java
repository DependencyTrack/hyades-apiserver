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
package org.dependencytrack.dex.activity;

import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @since 5.7.0
 */
@ActivitySpec(name = "delete-files")
public final class DeleteFilesActivity implements Activity<DeleteFilesArgument, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DeleteFilesActivity.class);

    private final PluginManager pluginManager;

    public DeleteFilesActivity(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable DeleteFilesArgument argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }
        if (argument.getFileMetadataCount() == 0) {
            return null;
        }

        final Map<String, List<FileMetadata>> fileMetadataByProvider =
                argument.getFileMetadataList().stream()
                        .collect(Collectors.groupingBy(FileMetadata::getProviderName));

        for (final String providerName : fileMetadataByProvider.keySet()) {
            try (final var fileStorage = pluginManager.getExtension(FileStorage.class, providerName)) {

                // TODO: Call fileStorage#deleteMany here once available.
                for (final FileMetadata fileMetadata : fileMetadataByProvider.get(providerName)) {
                    LOGGER.debug("Deleting file {}", fileMetadata.getLocation());
                    fileStorage.delete(fileMetadata);
                }
            }
        }

        return null;
    }

}
