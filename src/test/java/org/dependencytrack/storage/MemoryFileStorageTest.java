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

import org.dependencytrack.plugin.MockConfigRegistry;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class MemoryFileStorageTest {

    @Test
    public void shouldHaveNameMemory() {
        final var storageFactory = new MemoryFileStorageFactory();
        assertThat(storageFactory.extensionName()).isEqualTo("memory");
    }

    @Test
    public void shouldHavePriority110() {
        final var storageFactory = new MemoryFileStorageFactory();
        assertThat(storageFactory.priority()).isEqualTo(100);
    }

    @Test
    public void shouldStoreGetAndDeleteFile() throws Exception {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo", "bar".getBytes());
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getKey()).matches(".+_foo$");
        assertThat(fileMetadata.getStorageName()).isEqualTo("memory");
        assertThat(fileMetadata.getStorageMetadataMap()).isEmpty();

        final byte[] fileContent = storage.get(fileMetadata);
        assertThat(fileContent).isNotNull();
        assertThat(fileContent).asString().isEqualTo("bar");

        final boolean deleted = storage.delete(fileMetadata);
        assertThat(deleted).isTrue();
    }

    @Test
    public void shouldThrowWhenGettingFileFromDifferentStorage() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setKey("foo")
                                .setStorageName("bar")
                                .build()))
                .withMessage("Unable to retrieve file from storage: bar");
    }

    @Test
    public void shouldThrowWhenStoringFileWithInvalidName() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("/../../foo", "bar".getBytes()))
                .withMessage("name must match pattern: [a-zA-Z0-9_\\-.]+");
    }

    @Test
    public void shouldReturnFalseWhenDeletingNonExistentFile() throws Exception {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setKey("foo")
                        .setStorageName("memory")
                        .build());
        assertThat(deleted).isFalse();
    }

    @Test
    public void shouldThrowWhenDeletingFileFromDifferentStorage() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.delete(
                        FileMetadata.newBuilder()
                                .setKey("foo")
                                .setStorageName("bar")
                                .build()))
                .withMessage("Unable to delete file from storage: bar");
    }

}