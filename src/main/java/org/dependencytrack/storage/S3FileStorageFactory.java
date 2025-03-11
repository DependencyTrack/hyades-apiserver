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

import alpine.Config;
import io.minio.BucketExistsArgs;
import io.minio.MinioClient;
import org.dependencytrack.plugin.api.ConfigDefinition;
import org.dependencytrack.plugin.api.ConfigRegistry;
import org.dependencytrack.plugin.api.ConfigSource;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * @since 5.6.0
 */
public final class S3FileStorageFactory implements ExtensionFactory<FileStorage> {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3FileStorageFactory.class);

    static final ConfigDefinition CONFIG_ENDPOINT = new ConfigDefinition(
            "endpoint",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ true,
            /* isSecret */ false);
    static final ConfigDefinition CONFIG_BUCKET = new ConfigDefinition(
            "bucket",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ true,
            /* isSecret */ false);
    static final ConfigDefinition CONFIG_ACCESS_KEY = new ConfigDefinition(
            "access.key",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ true);
    static final ConfigDefinition CONFIG_SECRET_KEY = new ConfigDefinition(
            "secret.key",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ true);
    static final ConfigDefinition CONFIG_REGION = new ConfigDefinition(
            "region",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);
    static final ConfigDefinition CONFIG_COMPRESSION_THRESHOLD_BYTES = new ConfigDefinition(
            "compression.threshold.bytes",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);
    static final ConfigDefinition CONFIG_COMPRESSION_LEVEL = new ConfigDefinition(
            "compression.level",
            ConfigSource.DEPLOYMENT,
            /* isRequired */ false,
            /* isSecret */ false);

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
    public void init(final ConfigRegistry configRegistry) {
        final String endpoint = configRegistry.getValue(CONFIG_ENDPOINT);
        bucketName = configRegistry.getValue(CONFIG_BUCKET);
        final Optional<String> optionalAccessKey = configRegistry.getOptionalValue(CONFIG_ACCESS_KEY);
        final Optional<String> optionalSecretKey = configRegistry.getOptionalValue(CONFIG_SECRET_KEY);
        final Optional<String> optionalRegion = configRegistry.getOptionalValue(CONFIG_REGION);

        final var clientBuilder = MinioClient.builder().endpoint(endpoint);
        if (optionalAccessKey.isPresent() && optionalSecretKey.isPresent()) {
            clientBuilder.credentials(optionalAccessKey.get(), optionalSecretKey.get());
        }
        optionalRegion.ifPresent(clientBuilder::region);
        s3Client = clientBuilder.build();

        s3Client.setAppInfo(
                Config.getInstance().getApplicationName(),
                Config.getInstance().getApplicationVersion());

        compressionThresholdBytes = configRegistry.getOptionalValue(CONFIG_COMPRESSION_THRESHOLD_BYTES)
                .map(Integer::parseInt)
                .orElse(4096);
        compressionLevel = configRegistry.getOptionalValue(CONFIG_COMPRESSION_LEVEL)
                .map(Integer::parseInt)
                .orElse(5);

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
