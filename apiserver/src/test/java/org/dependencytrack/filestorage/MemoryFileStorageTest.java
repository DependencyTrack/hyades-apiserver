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

import org.dependencytrack.plugin.MockConfigRegistry;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class MemoryFileStorageTest {

    @Test
    @SuppressWarnings("resource")
    public void shouldHaveNameMemory() {
        final var storageFactory = new MemoryFileStorageFactory();
        assertThat(storageFactory.extensionName()).isEqualTo("memory");
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldHavePriority110() {
        final var storageFactory = new MemoryFileStorageFactory();
        assertThat(storageFactory.priority()).isEqualTo(110);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldStoreGetAndDeleteFile() throws Exception {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo/bar", "baz".getBytes());
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getLocation()).isEqualTo("memory:///foo/bar");
        assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
        assertThat(fileMetadata.getSha256Digest()).isEqualTo("baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096");

        final byte[] fileContent = storage.get(fileMetadata);
        assertThat(fileContent).isNotNull();
        assertThat(fileContent).asString().isEqualTo("baz");

        final boolean deleted = storage.delete(fileMetadata);
        assertThat(deleted).isTrue();
        assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
    }

    @Test
    @SuppressWarnings("resource")
    public void storeShouldOverwriteExistingFile() throws Exception {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadataA = storage.store("foo/bar", "baz".getBytes());
        final FileMetadata fileMetadataB = storage.store("foo/bar", "qux".getBytes());

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> storage.get(fileMetadataA))
                .withMessage("""
                        SHA256 digest mismatch: \
                        actual=21f58d27f827d295ffcd860c65045685e3baf1ad4506caa0140113b316647534, \
                        expected=baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096""");

        assertThat(storage.get(fileMetadataB)).asString().isEqualTo("qux");
    }

    @Test
    @SuppressWarnings("resource")
    public void storeShouldThrowWhenFileHasInvalidName() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo$bar", "bar".getBytes()))
                .withMessage("fileName must match pattern: [a-zA-Z0-9_/\\-.]+");
    }

    @Test
    @SuppressWarnings("resource")
    public void getShouldThrowWhenFileDoesNotExist() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(NoSuchFileException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("memory:///foo/bar")
                                .setSha256Digest("some-digest")
                                .build()));
    }

    @Test
    @SuppressWarnings("resource")
    public void getShouldThrowWhenFileLocationHasInvalidScheme() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected memory");
    }

    @Test
    @SuppressWarnings("resource")
    public void deleteShouldReturnFalseWhenFileDoesNotExist() throws Exception {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setLocation("memory:///foo")
                        .build());
        assertThat(deleted).isFalse();
    }

    @Test
    @SuppressWarnings("resource")
    public void deleteShouldThrowWhenFileLocationHasInvalidScheme() {
        final var storageFactory = new MemoryFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Collections.emptyMap()));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.delete(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected memory");
    }

}