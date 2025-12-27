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
package org.dependencytrack.filestorage.s3;

import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.filestorage.FileStorage;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.nio.file.NoSuchFileException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class S3FileStorageTest {

    private MinIOContainer minioContainer;
    private MinioClient s3Client;

    @BeforeEach
    void beforeEach() throws Exception {
        minioContainer = new MinIOContainer(DockerImageName.parse("minio/minio:latest"));
        minioContainer.start();

        s3Client = MinioClient.builder()
                .endpoint(minioContainer.getS3URL())
                .credentials(minioContainer.getUserName(), minioContainer.getPassword())
                .build();

        s3Client.makeBucket(MakeBucketArgs.builder()
                .bucket("test")
                .build());
    }

    @AfterEach
    void afterEach() throws Exception {
        if (s3Client != null) {
            s3Client.close();
        }
        if (minioContainer != null) {
            minioContainer.stop();
        }
    }

    @Test
    void shouldHaveNameS3() {
        try (final var storageFactory = new S3FileStorageFactory()) {
            assertThat(storageFactory.extensionName()).isEqualTo("s3");
        }
    }

    @Test
    void shouldHavePriority120() {
        try (final var storageFactory = new S3FileStorageFactory()) {
            assertThat(storageFactory.priority()).isEqualTo(120);
        }
    }

    @Test
    void initShouldThrowWhenBucketDoesNotExist() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "does-not-exist")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> storageFactory.init(new ExtensionContext(configRegistry)))
                    .withMessage("Bucket does-not-exist does not exist");
        }
    }

    @Test
    void initShouldThrowWhenBucketExistenceCheckFailed() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "does-not-exist")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            minioContainer.stop();

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> storageFactory.init(new ExtensionContext(configRegistry)))
                    .withMessage("Failed to determine if bucket does-not-exist exists");
        }
    }

    @Test
    void shouldStoreAndGetAndDeleteFile() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadata = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
            assertThat(fileMetadata.getLocation()).isEqualTo("s3://test/foo/bar");
            assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
            assertThat(fileMetadata.getSha256Digest()).isEqualTo("018e647e32f8c2b320b731ddd7de9842616209d93a3aeeea985a48b7fe0e5eda");

            final InputStream fileStream = storage.get(fileMetadata);
            assertThat(fileStream).isNotNull();
            assertThat(fileStream.readAllBytes()).asString().isEqualTo("baz");

            assertThat(storage.delete(fileMetadata)).isTrue();
            assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
        }
    }

    @Test
    void storeShouldOverwriteExistingFile() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadataA = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
            final FileMetadata fileMetadataB = storage.store("foo/bar", new ByteArrayInputStream("qux".getBytes()));

            assertThat(storage.get(fileMetadataA).readAllBytes()).asString().isEqualTo("qux");
            assertThat(storage.get(fileMetadataB).readAllBytes()).asString().isEqualTo("qux");
        }
    }

    @Test
    void storeShouldThrowWhenFileHasInvalidName() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            minioContainer.stop();

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> storage.store("foo$bar", new ByteArrayInputStream("bar".getBytes())))
                    .withMessage("fileName must match pattern: [a-zA-Z0-9_/\\-.]+");
        }
    }

    @Test
    void storeShouldThrowWhenHostIsUnavailable() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            minioContainer.stop();

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.store("foo", new ByteArrayInputStream("bar".getBytes())));
        }
    }

    @Test
    void getShouldThrowWhenFileDoesNotExist() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            assertThatExceptionOfType(NoSuchFileException.class)
                    .isThrownBy(() -> storage.get(
                            FileMetadata.newBuilder()
                                    .setLocation("s3://test/foo/bar")
                                    .setSha256Digest("some-digest")
                                    .build()));
        }
    }

    @Test
    void getShouldThrowWhenHostIsUnavailable() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("bar".getBytes()));

            minioContainer.stop();

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.get(fileMetadata))
                    .withCauseInstanceOf(ConnectException.class);
        }
    }

    @Test
    void deleteShouldReturnTrueWhenFileDoesNotExist() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            assertThat(storage.delete(
                    FileMetadata.newBuilder()
                            .setLocation("s3://test/foo")
                            .build())).isTrue();
        }
    }

    @Test
    void deleteShouldThrowWhenHostIsUnavailable() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry("endpoint", minioContainer.getS3URL()),
                Map.entry("access.key", minioContainer.getUserName()),
                Map.entry("secret.key", minioContainer.getPassword()),
                Map.entry("bucket", "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(new ExtensionContext(configRegistry));

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("bar".getBytes()));

            minioContainer.stop();

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.delete(fileMetadata))
                    .withCauseInstanceOf(ConnectException.class);
        }
    }

}