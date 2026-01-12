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
package org.dependencytrack.filestorage.memory;

import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.api.FileStorageFactory;
import org.dependencytrack.plugin.api.ExtensionContext;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @since 5.6.0
 */
final class MemoryFileStorageFactory implements FileStorageFactory {

    private final Map<String, byte[]> fileContentByKey = new ConcurrentHashMap<>();

    @Override
    public String extensionName() {
        return MemoryFileStorage.EXTENSION_NAME;
    }

    @Override
    public Class<? extends FileStorage> extensionClass() {
        return MemoryFileStorage.class;
    }

    @Override
    public int priority() {
        return 110;
    }

    @Override
    public void init(final ExtensionContext ctx) {
    }

    @Override
    public FileStorage create() {
        return new MemoryFileStorage(fileContentByKey);
    }

}
