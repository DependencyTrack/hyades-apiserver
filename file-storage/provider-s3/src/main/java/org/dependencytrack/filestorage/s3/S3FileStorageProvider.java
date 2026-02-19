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
import org.dependencytrack.filestorage.api.FileStorageProvider;
import org.eclipse.microprofile.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ProxySelector;

/**
 * @since 5.7.0
 */
public final class S3FileStorageProvider implements FileStorageProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3FileStorageProvider.class);
    static final String NAME = "s3";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public FileStorage create(Config config, ProxySelector proxySelector) {
        final String endpoint = config.getValue("dt.file-storage.s3.endpoint", String.class);
        final String bucketName = config.getValue("dt.file-storage.s3.bucket", String.class);
        final String accessKey = config.getOptionalValue("dt.file-storage.s3.access.key", String.class).orElse(null);
        final String secretKey = config.getOptionalValue("dt.file-storage.s3.secret.key", String.class).orElse(null);
        final String region = config.getOptionalValue("dt.file-storage.s3.region", String.class).orElse(null);

        final var httpClient = new OkHttpClient.Builder()
                .proxySelector(proxySelector)
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
        final MinioClient s3Client = clientBuilder.build();

        LOGGER.debug("Verifying existence of bucket {}", bucketName);
        requireBucketExists(s3Client, bucketName);

        final int compressionLevel = config
                .getOptionalValue("dt.file-storage.s3.compression.level", int.class)
                .orElse(5);
        if (compressionLevel < Zstd.minCompressionLevel() || compressionLevel > Zstd.maxCompressionLevel()) {
            throw new IllegalStateException(
                    "Invalid compression level: must be between %d and %d, but is %d".formatted(
                            Zstd.minCompressionLevel(),
                            Zstd.maxCompressionLevel(),
                            compressionLevel));
        }

        return new S3FileStorage(s3Client, bucketName, compressionLevel);
    }

    private static void requireBucketExists(MinioClient s3Client, String bucketName) {
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
