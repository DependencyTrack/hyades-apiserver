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
import org.dependencytrack.storage.MemoryFileStorageFactory.StoredFile;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.Map;
import java.util.UUID;

class MemoryFileStorage implements FileStorage {

    static final String EXTENSION_NAME = "memory";

    private final Map<String, StoredFile> storedFileByKey;

    MemoryFileStorage(final Map<String, StoredFile> storedFileByKey) {
        this.storedFileByKey = storedFileByKey;
    }

    @Override
    public FileMetadata store(final String name, final byte[] content) throws IOException {
        final String key = "%s-%s".formatted(UUID.randomUUID().toString(), name);
        final String sha256 = DigestUtils.sha256Hex(content);

        storedFileByKey.put(key, new StoredFile(key, sha256, content));
        return new FileMetadata(key, "memory", sha256);
    }

    @Override
    public byte[] get(final String key) throws IOException {
        final StoredFile storedFile = storedFileByKey.get(key);
        if (storedFile == null) {
            throw new NoSuchFileException(key);
        }

        return storedFile.content();
    }

    @Override
    public boolean delete(final String key) throws IOException {
        return storedFileByKey.remove(key) != null;
    }

}
