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

import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.containers.MinIOContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.plugin.PluginManagerTestUtil.createConfigRegistry;
import static org.dependencytrack.storage.BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME;

public class S3BomUploadStorageTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private MinIOContainer minioContainer;
    private MinioClient s3Client;

    @Before
    public void before() throws Exception {
        minioContainer = new MinIOContainer(DockerImageName.parse("minio/minio:RELEASE.2023-12-14T18-51-57Z"));
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
    public void testFactoryName() {
        try (final var factory = new S3BomUploadStorageFactory()) {
            assertThat(factory.extensionName()).isEqualTo("s3");
        }
    }

    @Test
    public void testFactoryPriority() {
        try (final var factory = new S3BomUploadStorageFactory()) {
            assertThat(factory.priority()).isEqualTo(120);
        }
    }

    @Test
    public void testFactoryInitWhenBucketDoesNotExist() {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "not-not-exist");

        try (final var factory = new S3BomUploadStorageFactory()) {
            final ConfigRegistry configRegistry = createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME);
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> factory.init(configRegistry))
                    .withMessage("Bucket not-not-exist does not exist");
        }
    }

    @Test
    public void testFactoryInitWithErrorOnBucketExistsCheck() {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "not-not-exist");

        try (final var factory = new S3BomUploadStorageFactory()) {
            final ConfigRegistry configRegistry = createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME);

            minioContainer.stop();

            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> factory.init(configRegistry))
                    .withMessage("Failed to determine if bucket not-not-exist exists");
        }
    }

    @Test
    public void testStoreAndGetAndDeleteBom() throws Exception {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "test");

        try (final var factory = new S3BomUploadStorageFactory()) {
            factory.init(createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            final var token = UUID.randomUUID();
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "foo".getBytes()));
            assertThat(storage.getBomByToken(token)).asString().isEqualTo("foo");
            assertThat(storage.deleteBomByToken(token)).isTrue();
            assertThat(storage.getBomByToken(token)).isNull();
        }
    }

    @Test
    public void testStoreBomDuplicate() throws Exception {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "test");

        try (final var factory = new S3BomUploadStorageFactory()) {
            factory.init(createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            final var token = UUID.randomUUID();
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "foo".getBytes()));
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "bar".getBytes()));
            assertThat(storage.getBomByToken(token)).asString().isEqualTo("bar");
        }
    }

    @Test
    public void testStoreBomError() {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "test");

        try (final var factory = new S3BomUploadStorageFactory()) {
            factory.init(createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            minioContainer.stop();

            final var token = UUID.randomUUID();
            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.storeBom(token, "foo".getBytes()))
                    .withMessage("Failed to store BOM for token %s".formatted(token));
        }
    }

    @Test
    public void testGetBomError() {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "test");

        try (final var factory = new S3BomUploadStorageFactory()) {
            factory.init(createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            minioContainer.stop();

            final var token = UUID.randomUUID();
            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.getBomByToken(token))
                    .withMessage("Failed to get BOM for token %s".formatted(token));
        }
    }

    @Test
    public void testDeleteNonExistentBom() throws Exception {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "test");

        try (final var factory = new S3BomUploadStorageFactory()) {
            factory.init(createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            assertThat(storage.deleteBomByToken(UUID.randomUUID())).isTrue();
        }
    }

    @Test
    public void testDeleteBomError() {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ENDPOINT", minioContainer.getS3URL());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_ACCESS_KEY", minioContainer.getUserName());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_SECRET_KEY", minioContainer.getPassword());
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_S3_BUCKET", "test");

        try (final var factory = new S3BomUploadStorageFactory()) {
            factory.init(createConfigRegistry(EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            minioContainer.stop();

            final var token = UUID.randomUUID();
            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> storage.deleteBomByToken(token))
                    .withMessage("Failed to delete BOM for token %s".formatted(token));
        }
    }

}