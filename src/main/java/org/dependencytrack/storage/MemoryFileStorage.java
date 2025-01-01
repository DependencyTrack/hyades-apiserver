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

import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.storage.FileStorage.requireValidName;

final class MemoryFileStorage implements FileStorage {

    static final String EXTENSION_NAME = "memory";

    private final Map<String, byte[]> fileContentByKey;

    MemoryFileStorage(final Map<String, byte[]> fileContentByKey) {
        this.fileContentByKey = requireNonNull(fileContentByKey);
    }

    @Override
    public FileMetadata store(final String name, final byte[] content) throws IOException {
        requireValidName(name);
        requireNonNull(content, "content must not be null");

        final String key = "%s_%s".formatted(UUID.randomUUID().toString(), name);

        fileContentByKey.put(key, content);
        return FileMetadata.newBuilder()
                .setKey(key)
                .setStorageName(EXTENSION_NAME)
                .build();
    }

    @Override
    public byte[] get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        if (!EXTENSION_NAME.equals(fileMetadata.getStorageName())) {
            throw new IllegalArgumentException("Unable to retrieve file from storage: " + fileMetadata.getStorageName());
        }

        final byte[] fileContent = fileContentByKey.get(fileMetadata.getKey());
        if (fileContent == null) {
            throw new NoSuchFileException(fileMetadata.getKey());
        }

        return fileContent;
    }

    @Override
    public boolean delete(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        if (!EXTENSION_NAME.equals(fileMetadata.getStorageName())) {
            throw new IllegalArgumentException("Unable to delete file from storage: " + fileMetadata.getStorageName());
        }

        return fileContentByKey.remove(fileMetadata.getKey()) != null;
    }

}
