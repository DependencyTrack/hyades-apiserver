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

import io.minio.GetObjectArgs;
import io.minio.GetObjectResponse;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.plugin.MockConfigRegistry;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.ConnectException;
import java.nio.file.NoSuchFileException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.filestorage.LocalFileStorageFactory.CONFIG_COMPRESSION_THRESHOLD_BYTES;
import static org.dependencytrack.filestorage.S3FileStorageFactory.CONFIG_ACCESS_KEY;
import static org.dependencytrack.filestorage.S3FileStorageFactory.CONFIG_BUCKET;
import static org.dependencytrack.filestorage.S3FileStorageFactory.CONFIG_ENDPOINT;
import static org.dependencytrack.filestorage.S3FileStorageFactory.CONFIG_SECRET_KEY;

public class S3FileStorageTest {

    private MinIOContainer minioContainer;
    private MinioClient s3Client;

    @Before
    public void before() throws Exception {
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

    @After
    public void after() throws Exception {
        if (s3Client != null) {
            s3Client.close();
        }
        if (minioContainer != null) {
            minioContainer.stop();
        }
    }

    @Test
    public void shouldHaveNameS3() {
        try (final var storageFactory = new S3FileStorageFactory()) {
            assertThat(storageFactory.extensionName()).isEqualTo("s3");
        }
    }

    @Test
    public void shouldHavePriority120() {
        try (final var storageFactory = new S3FileStorageFactory()) {
            assertThat(storageFactory.priority()).isEqualTo(120);
        }
    }

    @Test
    public void initShouldThrowWhenBucketDoesNotExist() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "does-not-exist")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> storageFactory.init(configRegistry))
                    .withMessage("Bucket does-not-exist does not exist");
        }
    }

    @Test
    public void initShouldThrowWhenBucketExistenceCheckFailed() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "does-not-exist")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            minioContainer.stop();

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> storageFactory.init(configRegistry))
                    .withMessage("Failed to determine if bucket does-not-exist exists");
        }
    }

    @Test
    public void shouldStoreAndGetAndDeleteFile() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadata = storage.store("foo/bar", "baz".getBytes());
            assertThat(fileMetadata.getLocation()).isEqualTo("s3://test/foo/bar");
            assertThat(fileMetadata.getMediaType()).isEqualTo("application/octet-stream");
            assertThat(fileMetadata.getSha256Digest()).isEqualTo("baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096");

            final byte[] fileContent = storage.get(fileMetadata);
            assertThat(fileContent).isNotNull();
            assertThat(fileContent).asString().isEqualTo("baz");

            assertThat(storage.delete(fileMetadata)).isTrue();
            assertThatExceptionOfType(NoSuchFileException.class).isThrownBy(() -> storage.get(fileMetadata));
        }
    }

    @Test
    public void storeShouldCompressFileWithSizeAboveCompressionThreshold() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test"),
                Map.entry(CONFIG_COMPRESSION_THRESHOLD_BYTES.name(), "64")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            final byte[] fileContent = "a".repeat(256).getBytes();
            final String fileContentDigestHex = DigestUtils.sha256Hex(fileContent);

            final FileMetadata fileMetadata = storage.store("foo/bar", fileContent);
            assertThat(fileMetadata).isNotNull();

            // Digest must be calculated on the compressed file content.
            assertThat(fileMetadata.getSha256Digest()).isNotEqualTo(fileContentDigestHex);

            // File on disk must in fact be smaller as a result of compression.
            final GetObjectResponse response = s3Client.getObject(
                    GetObjectArgs.builder()
                            .bucket("test")
                            .object("foo/bar")
                            .build());
            assertThat(response.readAllBytes()).hasSizeLessThan(32);

            // File must be transparently decompressed during retrieval.
            final byte[] retrievedFileContent = storage.get(fileMetadata);
            assertThat(retrievedFileContent).isEqualTo(fileContent);
        }
    }

    @Test
    public void storeShouldOverwriteExistingFile() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

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
    }

    @Test
    public void storeShouldThrowWhenFileHasInvalidName() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            minioContainer.stop();

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> storage.store("foo$bar", "bar".getBytes()))
                    .withMessage("fileName must match pattern: [a-zA-Z0-9_/\\-.]+");
        }
    }

    @Test
    public void storeShouldThrowWhenHostIsUnavailable() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            minioContainer.stop();

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.store("foo", "bar".getBytes()));
        }
    }

    @Test
    public void getShouldThrowWhenFileDoesNotExist() {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

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
    public void getShouldThrowWhenHostIsUnavailable() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadata = storage.store("foo", "bar".getBytes());

            minioContainer.stop();

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.get(fileMetadata))
                    .withCauseInstanceOf(ConnectException.class);
        }
    }

    @Test
    public void deleteShouldReturnTrueWhenFileDoesNotExist() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            assertThat(storage.delete(
                    FileMetadata.newBuilder()
                            .setLocation("s3://test/foo")
                            .build())).isTrue();
        }
    }

    @Test
    public void deleteShouldThrowWhenHostIsUnavailable() throws Exception {
        final var configRegistry = new MockConfigRegistry(Map.ofEntries(
                Map.entry(CONFIG_ENDPOINT.name(), minioContainer.getS3URL()),
                Map.entry(CONFIG_ACCESS_KEY.name(), minioContainer.getUserName()),
                Map.entry(CONFIG_SECRET_KEY.name(), minioContainer.getPassword()),
                Map.entry(CONFIG_BUCKET.name(), "test")));

        try (final var storageFactory = new S3FileStorageFactory()) {
            storageFactory.init(configRegistry);

            final FileStorage storage = storageFactory.create();

            final FileMetadata fileMetadata = storage.store("foo", "bar".getBytes());

            minioContainer.stop();

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.delete(fileMetadata))
                    .withCauseInstanceOf(ConnectException.class);
        }
    }

}