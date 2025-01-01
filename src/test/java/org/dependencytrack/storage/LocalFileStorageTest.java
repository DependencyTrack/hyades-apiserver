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
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.shaded.org.bouncycastle.jcajce.provider.digest.Blake3;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.storage.LocalFileStorageFactory.CONFIG_COMPRESSION_THRESHOLD_BYTES;
import static org.dependencytrack.storage.LocalFileStorageFactory.CONFIG_DIRECTORY;

public class LocalFileStorageTest {

    private Path tempDirPath;

    @Before
    public void before() throws Exception {
        tempDirPath = Files.createTempDirectory(null);
        tempDirPath.toFile().deleteOnExit();
    }

    @Test
    public void shouldHaveNameLocal() {
        final var storageFactory = new LocalFileStorageFactory();
        assertThat(storageFactory.extensionName()).isEqualTo("local");
    }

    @Test
    public void shouldHavePriority110() {
        final var storageFactory = new LocalFileStorageFactory();
        assertThat(storageFactory.priority()).isEqualTo(110);
    }

    @Test
    public void shouldStoreGetAndDeleteFile() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo", "bar".getBytes());
        assertThat(fileMetadata).isNotNull();
        assertThat(fileMetadata.getKey()).matches(".+_foo$");
        assertThat(fileMetadata.getStorageName()).isEqualTo("local");
        assertThat(fileMetadata.getStorageMetadataMap()).containsExactly(
                Map.entry("blake3_digest", "f2e897eed7d206cd855d441598fa521abc75aa96953e97c030c9612c30c1293d"));

        final byte[] fileContent = storage.get(fileMetadata);
        assertThat(fileContent).isNotNull();
        assertThat(fileContent).asString().isEqualTo("bar");

        final boolean deleted = storage.delete(fileMetadata);
        assertThat(deleted).isTrue();
    }

    @Test
    public void shouldCompressFileWithSizeAboveCompressionThreshold() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString()),
                Map.entry(CONFIG_COMPRESSION_THRESHOLD_BYTES.name(), "64"))));

        final var storage = (LocalFileStorage) storageFactory.create();

        final byte[] fileContent = "a".repeat(256).getBytes();
        final byte[] fileContentDigest = new Blake3.Blake3_256().digest(fileContent);
        final String fileContentDigestHex = HexFormat.of().formatHex(fileContentDigest);

        final FileMetadata fileMetadata = storage.store("foo", fileContent);
        assertThat(fileMetadata).isNotNull();

        // Digest must be calculated on the compressed file content.
        assertThat(fileMetadata.getStorageMetadataMap()).hasEntrySatisfying(
                "blake3_digest", value -> assertThat(value).isNotEqualTo(fileContentDigestHex));

        // File on disk must in fact be smaller as a result of compression.
        final Path filePath = storage.resolveFilePath(fileMetadata.getKey());
        assertThat(Files.readAllBytes(filePath)).hasSizeLessThan(32);

        // File must be transparently decompressed during retrieval.
        final byte[] retrievedFileContent = storage.get(fileMetadata);
        assertThat(retrievedFileContent).isEqualTo(fileContent);
    }

    @Test
    public void shouldThrowWhenGettingFileFromDifferentStorage() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

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
    public void shouldThrowWhenGettingFileWithDigestMismatch() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        final FileMetadata fileMetadata = storage.store("foo", "bar".getBytes());

        // It doesn't matter whether we modify the expected digest, or the actual file content.
        // Modifying the expected digest is easier for testing purposes.
        final FileMetadata modifiedFileMetadata = fileMetadata.toBuilder()
                .putStorageMetadata("blake3_digest", HexFormat.of().formatHex("mismatch".getBytes()))
                .build();

        assertThatExceptionOfType(IOException.class)
                .isThrownBy(() -> storage.get(modifiedFileMetadata))
                .withMessage("""
                        File digest mismatch: \
                        actual=f2e897eed7d206cd855d441598fa521abc75aa96953e97c030c9612c30c1293d, \
                        expected=6d69736d61746368""");
    }

    @Test
    public void shouldThrowWhenStoringFileWithInvalidName() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> storage.store("/../../foo", "bar".getBytes()))
                .withMessage("name must match pattern: [a-zA-Z0-9_\\-.]+");
    }

    @Test
    public void shouldReturnFalseWhenDeletingNonExistentFile() throws Exception {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

        final FileStorage storage = storageFactory.create();

        final boolean deleted = storage.delete(
                FileMetadata.newBuilder()
                        .setKey("foo")
                        .setStorageName("local")
                        .build());
        assertThat(deleted).isFalse();
    }

    @Test
    public void shouldThrowWhenDeletingFileFromDifferentStorage() {
        final var storageFactory = new LocalFileStorageFactory();
        storageFactory.init(new MockConfigRegistry(Map.of(
                CONFIG_DIRECTORY.name(), tempDirPath.toAbsolutePath().toString())));

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