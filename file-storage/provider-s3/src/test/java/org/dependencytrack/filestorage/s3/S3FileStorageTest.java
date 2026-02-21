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
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.ProxySelector;
import java.nio.file.NoSuchFileException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class S3FileStorageTest {

    private static MinIOContainer minioContainer;

    @BeforeAll
    static void beforeAll() throws Exception {
        minioContainer = new MinIOContainer(DockerImageName.parse("minio/minio:latest"));
        minioContainer.start();

        try (var s3Client = MinioClient.builder()
                .endpoint(minioContainer.getS3URL())
                .credentials(minioContainer.getUserName(), minioContainer.getPassword())
                .build()) {
            s3Client.makeBucket(MakeBucketArgs.builder()
                    .bucket("test")
                    .build());
        }
    }

    @AfterAll
    static void afterAll() {
        if (minioContainer != null) {
            minioContainer.stop();
        }
    }

    @Test
    void shouldHaveNameS3() {
        final var provider = new S3FileStorageProvider();
        assertThat(provider.name()).isEqualTo("s3");
    }

    @Test
    void shouldThrowWhenBucketDoesNotExist() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(Map.ofEntries(
                        Map.entry("dt.file-storage.s3.endpoint", minioContainer.getS3URL()),
                        Map.entry("dt.file-storage.s3.access.key", minioContainer.getUserName()),
                        Map.entry("dt.file-storage.s3.secret.key", minioContainer.getPassword()),
                        Map.entry("dt.file-storage.s3.bucket", "does-not-exist"))))
                .withMessage("Bucket does-not-exist does not exist");
    }

    @Test
    void shouldThrowWhenBucketExistenceCheckFailed() {
        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(Map.ofEntries(
                        Map.entry("dt.file-storage.s3.endpoint", "http://localhost:1"),
                        Map.entry("dt.file-storage.s3.access.key", "minioadmin"),
                        Map.entry("dt.file-storage.s3.secret.key", "minioadmin"),
                        Map.entry("dt.file-storage.s3.bucket", "does-not-exist"),
                        Map.entry("dt.file-storage.s3.connect-timeout-ms", "500"))))
                .withMessage("Failed to determine if bucket does-not-exist exists");
    }

    @Test
    void shouldStoreAndGetAndDeleteFile() throws Exception {
        try (final FileStorage storage = createStorage()) {
            final FileMetadata fileMetadata = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
            assertThat(fileMetadata.getProviderName()).isEqualTo("s3");
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
        try (final FileStorage storage = createStorage()) {
            final FileMetadata fileMetadataA = storage.store("foo/bar", new ByteArrayInputStream("baz".getBytes()));
            final FileMetadata fileMetadataB = storage.store("foo/bar", new ByteArrayInputStream("qux".getBytes()));

            assertThat(storage.get(fileMetadataA).readAllBytes()).asString().isEqualTo("qux");
            assertThat(storage.get(fileMetadataB).readAllBytes()).asString().isEqualTo("qux");
        }
    }

    @Test
    void storeShouldThrowWhenFileHasInvalidName() throws Exception {
        try (final FileStorage storage = createStorage()) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> storage.store("foo$bar", new ByteArrayInputStream("bar".getBytes())))
                    .withMessage("fileName 'foo$bar' does not match pattern: [a-zA-Z0-9_/\\-.]+");
        }
    }

    @Test
    void getShouldThrowWhenFileDoesNotExist() throws Exception {
        try (final FileStorage storage = createStorage()) {
            assertThatExceptionOfType(NoSuchFileException.class)
                    .isThrownBy(() -> storage.get(
                            FileMetadata.newBuilder()
                                    .setLocation("s3://test/foo/bar")
                                    .setSha256Digest("some-digest")
                                    .build()));
        }
    }

    @Test
    void deleteShouldReturnTrueWhenFileDoesNotExist() throws Exception {
        try (final FileStorage storage = createStorage()) {
            assertThat(storage.delete(
                    FileMetadata.newBuilder()
                            .setLocation("s3://test/foo")
                            .build())).isTrue();
        }
    }

    @Nested
    class WhenHostIsUnavailable {

        private MinIOContainer ephemeralContainer;

        @BeforeEach
        void beforeEach() throws Exception {
            ephemeralContainer = new MinIOContainer(DockerImageName.parse("minio/minio:latest"));
            ephemeralContainer.start();

            try (var s3Client = MinioClient.builder()
                    .endpoint(ephemeralContainer.getS3URL())
                    .credentials(ephemeralContainer.getUserName(), ephemeralContainer.getPassword())
                    .build()) {
                s3Client.makeBucket(MakeBucketArgs.builder()
                        .bucket("test")
                        .build());
            }
        }

        @AfterEach
        void afterEach() {
            if (ephemeralContainer != null) {
                ephemeralContainer.stop();
            }
        }

        @Test
        void storeShouldThrowWhenHostIsUnavailable() throws Exception {
            try (final FileStorage storage = createEphemeralStorage()) {
                ephemeralContainer.stop();

                assertThatExceptionOfType(IOException.class)
                        .isThrownBy(() -> storage.store("foo", new ByteArrayInputStream("bar".getBytes())));
            }
        }

        @Test
        void getShouldThrowWhenHostIsUnavailable() throws Exception {
            try (final FileStorage storage = createEphemeralStorage()) {
                final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("bar".getBytes()));

                ephemeralContainer.stop();

                assertThatExceptionOfType(IOException.class)
                        .isThrownBy(() -> storage.get(fileMetadata))
                        .withCauseInstanceOf(ConnectException.class);
            }
        }

        @Test
        void deleteShouldThrowWhenHostIsUnavailable() throws Exception {
            try (final FileStorage storage = createEphemeralStorage()) {
                final FileMetadata fileMetadata = storage.store("foo", new ByteArrayInputStream("bar".getBytes()));

                ephemeralContainer.stop();

                assertThatExceptionOfType(IOException.class)
                        .isThrownBy(() -> storage.delete(fileMetadata))
                        .withCauseInstanceOf(ConnectException.class);
            }
        }

        private FileStorage createEphemeralStorage() {
            return createStorage(Map.ofEntries(
                    Map.entry("dt.file-storage.s3.endpoint", ephemeralContainer.getS3URL()),
                    Map.entry("dt.file-storage.s3.access.key", ephemeralContainer.getUserName()),
                    Map.entry("dt.file-storage.s3.secret.key", ephemeralContainer.getPassword()),
                    Map.entry("dt.file-storage.s3.bucket", "test"),
                    Map.entry("dt.file-storage.s3.connect-timeout-ms", "500"),
                    Map.entry("dt.file-storage.s3.read-timeout-ms", "500"),
                    Map.entry("dt.file-storage.s3.write-timeout-ms", "500")));
        }

    }

    private FileStorage createStorage() {
        return createStorage(Map.ofEntries(
                Map.entry("dt.file-storage.s3.endpoint", minioContainer.getS3URL()),
                Map.entry("dt.file-storage.s3.access.key", minioContainer.getUserName()),
                Map.entry("dt.file-storage.s3.secret.key", minioContainer.getPassword()),
                Map.entry("dt.file-storage.s3.bucket", "test")));
    }

    private static FileStorage createStorage(Map<String, String> configValues) {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(configValues)
                .build();
        return new S3FileStorageProvider().create(config, ProxySelector.getDefault());
    }

}
