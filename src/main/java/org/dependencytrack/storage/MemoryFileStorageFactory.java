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

import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ExtensionFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MemoryFileStorageFactory implements ExtensionFactory<FileStorage> {

    record StoredFile(String key, String sha256, byte[] content) {
    }

    private Map<String, StoredFile> storedFileByKey;

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
        return 100;
    }

    @Override
    public void init(final ConfigRegistry configRegistry) {
        storedFileByKey = new ConcurrentHashMap<>();
    }

    @Override
    public FileStorage create() {
        return new MemoryFileStorage(storedFileByKey);
    }

}