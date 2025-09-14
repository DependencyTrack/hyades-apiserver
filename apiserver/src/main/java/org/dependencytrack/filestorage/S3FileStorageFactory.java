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

import alpine.Config;
import io.minio.BucketExistsArgs;
import io.minio.MinioClient;
import okhttp3.OkHttpClient;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.config.ConfigDefinition;
import org.dependencytrack.plugin.api.config.ConfigTypes;
import org.dependencytrack.plugin.api.config.DeploymentConfigDefinition;
import org.dependencytrack.plugin.api.filestorage.FileStorage;
import org.dependencytrack.plugin.api.filestorage.FileStorageFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * @since 5.6.0
 */
public final class S3FileStorageFactory implements FileStorageFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3FileStorageFactory.class);

    static final ConfigDefinition<String> CONFIG_ENDPOINT =
            new DeploymentConfigDefinition<>("endpoint", ConfigTypes.STRING, /* isRequired */ true);
    static final ConfigDefinition<String> CONFIG_BUCKET =
            new DeploymentConfigDefinition<>("bucket", ConfigTypes.STRING, /* isRequired */ true);
    static final ConfigDefinition<String> CONFIG_ACCESS_KEY =
            new DeploymentConfigDefinition<>("access.key", ConfigTypes.STRING, /* isRequired */ false);
    static final ConfigDefinition<String> CONFIG_SECRET_KEY =
            new DeploymentConfigDefinition<>("secret.key", ConfigTypes.STRING, /* isRequired */ false);
    static final ConfigDefinition<String> CONFIG_REGION =
            new DeploymentConfigDefinition<>("region", ConfigTypes.STRING, /* isRequired */ false);
    static final ConfigDefinition<Integer> CONFIG_COMPRESSION_THRESHOLD_BYTES =
            new DeploymentConfigDefinition<>("compression.threshold.bytes", ConfigTypes.INTEGER, /* isRequired */ false);
    static final ConfigDefinition<Integer> CONFIG_COMPRESSION_LEVEL =
            new DeploymentConfigDefinition<>("compression.level", ConfigTypes.INTEGER, /* isRequired */ false);

    private MinioClient s3Client;
    private String bucketName;
    private int compressionThresholdBytes;
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
        final String endpoint = ctx.configRegistry().getValue(CONFIG_ENDPOINT);
        bucketName = ctx.configRegistry().getValue(CONFIG_BUCKET);
        final Optional<String> optionalAccessKey = ctx.configRegistry().getOptionalValue(CONFIG_ACCESS_KEY);
        final Optional<String> optionalSecretKey = ctx.configRegistry().getOptionalValue(CONFIG_SECRET_KEY);
        final Optional<String> optionalRegion = ctx.configRegistry().getOptionalValue(CONFIG_REGION);

        final var httpClient = new OkHttpClient.Builder()
                .proxySelector(ctx.proxySelector())
                .build();

        final var clientBuilder = MinioClient.builder()
                .httpClient(httpClient, /* close */ true)
                .endpoint(endpoint);
        if (optionalAccessKey.isPresent() && optionalSecretKey.isPresent()) {
            clientBuilder.credentials(optionalAccessKey.get(), optionalSecretKey.get());
        }
        optionalRegion.ifPresent(clientBuilder::region);
        s3Client = clientBuilder.build();

        s3Client.setAppInfo(
                Config.getInstance().getApplicationName(),
                Config.getInstance().getApplicationVersion());

        compressionThresholdBytes = ctx.configRegistry().getOptionalValue(CONFIG_COMPRESSION_THRESHOLD_BYTES).orElse(4096);
        compressionLevel = ctx.configRegistry().getOptionalValue(CONFIG_COMPRESSION_LEVEL).orElse(5);

        LOGGER.debug("Verifying existence of bucket {}", bucketName);
        requireBucketExists(s3Client, bucketName);
    }

    @Override
    public FileStorage create() {
        return new S3FileStorage(s3Client, bucketName, compressionThresholdBytes, compressionLevel);
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
