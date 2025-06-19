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

import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.plugin.MockConfigRegistry;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.filestorage.LocalFileStorageFactory.CONFIG_COMPRESSION_THRESHOLD_BYTES;
import static org.dependencytrack.filestorage.LocalFileStorageFactory.CONFIG_DIRECTORY;

public class LocalFileStorageTest {

    private Path tempDirPath;

    @Before
    public void before() throws Exception {
        tempDirPath = Files.createTempDirectory(null);
        tempDirPath.toFile().deleteOnExit();
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldHaveNameLocal() {
        final var storageFactory = new LocalFileStorageFactory();
        assertThat(storageFactory.extensionName()).isEqualTo("local");
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldHavePriority100() {
        final var storageFactory = new LocalFileStorageFactory();
        assertThat(storageFactory.priority()).isEqualTo(100);
    }

    @Test
    @SuppressWarnings("resource")
    public void shouldStoreGetAndDeleteFile() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo/bar", "baz".getBytes());
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getLocation()).isEqualTo("local:///foo/bar");
        assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
        assertThat(fileMetadata.getSha256Digest()).isEqualTo("baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096");

        assertThat(tempDirPath.resolve("foo/bar")).exists();

        final byte[] fileContent = storage.get(fileMetadata);
        assertThat(fileContent).isNotNull();
        assertThat(fileContent).asString().isEqualTo("baz");

        final boolean deleted = storage.delete(fileMetadata);
        assertThat(deleted).isTrue();
        assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
    }

    @Test
    @SuppressWarnings("resource")
    public void storeShouldCompressFileWithSizeAboveCompressionThreshold() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString()),
                Map.entry(CONFIG_COMPRESSION_THRESHOLD_BYTES.name(), "64"))));

        final var storage = (LocalFileStorage) storageFactory.create();

        final byte[] fileContent = "a".repeat(256).getBytes();
        final String fileContentDigestHex = DigestUtils.sha256Hex(fileContent);

        final FileMetadata fileMetadata = storage.store("foo", fileContent);
        assertThat(fileMetadata).isNotNull();

        // Digest must be calculated on the compressed file content.
        assertThat(fileMetadata.getSha256Digest()).isNotEqualTo(fileContentDigestHex);

        // File on disk must in fact be smaller as a result of compression.
        final Path filePath = storage.resolveFilePath(fileMetadata);
        assertThat(Files.readAllBytes(filePath)).hasSizeLessThan(32);

        // File must be transparently decompressed during retrieval.
        final byte[] retrievedFileContent = storage.get(fileMetadata);
        assertThat(retrievedFileContent).isEqualTo(fileContent);
    }

    @Test
    @SuppressWarnings("resource")
    public void storeShouldOverwriteExistingFile() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

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
    public void storeShouldThrowWhenFileNameAttemptsTraversal() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo/../../../bar", "bar".getBytes()))
                .withMessage("""
                        The provided filePath foo/../../../bar does not resolve to a path \
                        within the configured base directory (%s)""", tempDirPath);
    }

    @Test
    @SuppressWarnings("resource")
    public void storeShouldThrowWhenFileHasInvalidName() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("foo$bar", "bar".getBytes()))
                .withMessage("fileName must match pattern: [a-zA-Z0-9_/\\-.]+");
    }

    @Test
    @SuppressWarnings("resource")
    public void getShouldThrowWhenFileLocationHasInvalidScheme() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

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
    public void getShouldThrowWhenFileNameAttemptsTraversal() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

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
    public void getShouldThrowWhenFileDoesNotExist() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

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
    public void getShouldThrowWhenFileWithDigestMismatch() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo", "bar".getBytes());

        // It doesn't matter whether we modify the expected digest, or the actual file content.
        // Modifying the expected digest is easier for testing purposes.
        final FileMetadata modifiedFileMetadata = fileMetadata.toBuilder()
                .setSha256Digest(HexFormat.of().formatHex("mismatch".getBytes()))
                .build();

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> storage.get(modifiedFileMetadata))
                .withMessage("""
                        SHA256 digest mismatch: \
                        actual=fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9, \
                        expected=6d69736d61746368""");
    }

    @Test
    @SuppressWarnings("resource")
    public void deleteShouldReturnFalseWhenFileDoesNotExist() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setLocation("local:///foo")
                        .build());
        assertThat(deleted).isFalse();
    }

    @Test
    @SuppressWarnings("resource")
    public void deleteShouldThrowWhenFileLocationHasInvalidScheme() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.delete(
                        FileMetadata.newBuilder()
                                .setLocation("foo:///bar")
                                .build()))
                .withMessage("foo:///bar: Unexpected scheme foo, expected local");
    }

}