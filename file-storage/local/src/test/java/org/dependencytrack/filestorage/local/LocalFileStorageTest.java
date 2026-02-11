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
package org.dependencytrack.filestorage.local;

import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class LocalFileStorageTest {

    private Path tempDirPath;

    @BeforeEach
    void before() throws Exception {
        tempDirPath = Files.createTempDirectory(null);
        tempDirPath.toFile().deleteOnExit();
    }

    @Test
    @SuppressWarnings("resource")
    void shouldHaveNameLocal() {
        final var storageFactory = new LocalFileStorageFactory();
        assertThat(storageFactory.extensionName()).isEqualTo("local");
    }

    @Test
    @SuppressWarnings("resource")
    void shouldHavePriority100() {
        final var storageFactory = new LocalFileStorageFactory();
        assertThat(storageFactory.priority()).isEqualTo(100);
    }

    @Test
    @SuppressWarnings("resource")
    void shouldStoreGetAndDeleteFile() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getProviderName()).isEqualTo("local");
        assertThat(fileMetadata.getLocation()).isEqualTo("local:///foo/bar");
        assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
        assertThat(fileMetadata.getSha256Digest()).isEqualTo("018e647e32f8c2b320b731ddd7de9842616209d93a3aeeea985a48b7fe0e5eda");

        assertThat(tempDirPath.resolve("foo/bar")).exists();

        final InputStream fileStream = storage.get(fileMetadata);
        assertThat(fileStream).isNotNull();
        assertThat(fileStream.readAllBytes()).asString().isEqualTo("baz");

        final boolean deleted = storage.delete(fileMetadata);
        assertThat(deleted).isTrue();
        assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
        assertThat(tempDirPath.resolve("foo")).doesNotExist();
    }

    @Test
    @SuppressWarnings("resource")
    void storeShouldOverwriteExistingFile() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadataA = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
        final FileMetadata fileMetadataB = storage.store("foo/bar", new ByteArrayInputStream("qux".getBytes()));

        assertThat(storage.get(fileMetadataA).readAllBytes()).asString().isEqualTo("qux");
        assertThat(storage.get(fileMetadataB).readAllBytes()).asString().isEqualTo("qux");
    }

    @Test
    @SuppressWarnings("resource")
    void storeShouldThrowWhenFileNameAttemptsTraversal() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo/../../../bar", new ByteArrayInputStream("bar".getBytes())))
                .withMessage("""
                        The provided filePath foo/../../../bar does not resolve to a path \
                        within the configured base directory (%s)""", tempDirPath);
    }

    @Test
    @SuppressWarnings("resource")
    void storeShouldThrowWhenFileHasInvalidName() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo$bar", new ByteArrayInputStream("bar".getBytes())))
                .withMessage("fileName 'foo$bar' does not match pattern: [a-zA-Z0-9_/\\-.]+");
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileLocationHasInvalidScheme() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected local");
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileNameAttemptsTraversal() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("local:///foo/../../../bar")
                                .setSha256Digest("some-digest")
                                .build()))
                .withMessage("""
                        The provided filePath foo/../../../bar does not resolve to a path \
                        within the configured base directory (%s)""", tempDirPath);
    }

    @Test
    @SuppressWarnings("resource")
    void getShouldThrowWhenFileDoesNotExist() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(NoSuchFileException.class)
                .isThrownBy(() -> storage.get(
                        FileMetadata.newBuilder()
                                .setLocation("local:///foo/bar")
                                .setSha256Digest("some-digest")
                                .build()));
    }

    @Test
    @SuppressWarnings("resource")
    void deleteShouldNotDeleteNonEmptyParentDirs() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadataA = storage.store("foo/a", new ByteArrayInputStream("a".getBytes()));
        storage.store("foo/b", new ByteArrayInputStream("b".getBytes()));

        storage.delete(fileMetadataA);
        assertThat(tempDirPath.resolve("foo/a")).doesNotExist();
        assertThat(tempDirPath.resolve("foo")).exists();
    }

    @Test
    @SuppressWarnings("resource")
    void deleteShouldReturnFalseWhenFileDoesNotExist() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setLocation("local:///foo")
                        .build());
        assertThat(deleted).isFalse();
    }

    @Test
    @SuppressWarnings("resource")
    void deleteShouldThrowWhenFileLocationHasInvalidScheme() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new ExtensionContext(new MockConfigRegistry(Map.of(
                "directory", tempDirPath.toAbsolutePath().toString()))));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.delete(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected local");
    }

}