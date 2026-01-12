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

import com.github.luben.zstd.Zstd;
import io.minio.BucketExistsArgs;
import io.minio.MinioClient;
import okhttp3.OkHttpClient;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.api.FileStorageFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.DeploymentConfig;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @since 5.6.0
 */
public final class S3FileStorageFactory implements FileStorageFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3FileStorageFactory.class);

    private @Nullable MinioClient s3Client;
    private @Nullable String bucketName;
    private int compressionLevel;

    @Override
    public String extensionName() {
        return S3FileStorage.EXTENSION_NAME;
    }

    @Override
    public Class<? extends FileStorage> extensionClass() {
        return S3FileStorage.class;
    }

    @Override
    public int priority() {
        return 120;
    }

    @Override
    public void init(final ExtensionContext ctx) {
        final DeploymentConfig deploymentConfig = ctx.configRegistry().getDeploymentConfig();

        final String endpoint = deploymentConfig.getValue("endpoint", String.class);
        bucketName = deploymentConfig.getValue("bucket", String.class);
        final String accessKey = deploymentConfig.getOptionalValue("access.key", String.class).orElse(null);
        final String secretKey = deploymentConfig.getOptionalValue("secret.key", String.class).orElse(null);
        final String region = deploymentConfig.getOptionalValue("region", String.class).orElse(null);

        final var httpClient = new OkHttpClient.Builder()
                .proxySelector(ctx.proxySelector())
                .build();

        final var clientBuilder = MinioClient.builder()
                .httpClient(httpClient, /* close */ true)
                .endpoint(endpoint);
        if (accessKey != null && secretKey != null) {
            clientBuilder.credentials(accessKey, secretKey);
        }
        if (region != null) {
            clientBuilder.region(region);
        }
        s3Client = clientBuilder.build();

        LOGGER.debug("Verifying existence of bucket {}", bucketName);
        requireBucketExists(s3Client, bucketName);

        compressionLevel = deploymentConfig
                .getOptionalValue("compression.level", int.class)
                .orElse(5);
        if (compressionLevel < Zstd.minCompressionLevel() || compressionLevel > Zstd.maxCompressionLevel()) {
            throw new IllegalStateException(
                    "Invalid compression level: must be between %d and %d, but is %d".formatted(
                            Zstd.minCompressionLevel(),
                            Zstd.maxCompressionLevel(),
                            compressionLevel));
        }
    }

    @Override
    public FileStorage create() {
        return new S3FileStorage(s3Client, bucketName, compressionLevel);
    }

    @Override
    public void close() {
        if (s3Client != null) {
            LOGGER.debug("Closing S3 client");

            try {
                s3Client.close();
            } catch (Exception e) {
                LOGGER.warn("Failed to close s3 client", e);
            }
        }
    }

    private void requireBucketExists(final MinioClient s3Client, final String bucketName) {
        final boolean doesBucketExist;
        try {
            doesBucketExist = s3Client.bucketExists(
                    BucketExistsArgs.builder()
                            .bucket(bucketName)
                            .build());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to determine if bucket %s exists".formatted(bucketName), e);
        }

        if (!doesBucketExist) {
            throw new IllegalStateException("Bucket %s does not exist".formatted(bucketName));
        }
    }

}
