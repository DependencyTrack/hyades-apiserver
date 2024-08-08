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

import alpine.common.logging.Logger;
import io.minio.GetObjectArgs;
import io.minio.GetObjectResponse;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import io.minio.errors.ErrorResponseException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.UUID;

/**
 * A {@link BomUploadStorage} that stores uploaded BOMs in an S3 bucket.
 *
 * @since 5.6.0
 */
class S3BomUploadStorage implements BomUploadStorage {

    private static final Logger LOGGER = Logger.getLogger(S3BomUploadStorage.class);

    static final String EXTENSION_NAME = "s3";

    private final MinioClient s3Client;
    private final String bucketName;

    S3BomUploadStorage(final MinioClient s3Client, final String bucketName) {
        this.s3Client = s3Client;
        this.bucketName = bucketName;
    }

    @Override
    public void storeBom(final UUID token, final byte[] bom) throws IOException {
        try {
            s3Client.putObject(PutObjectArgs.builder()
                    .bucket(bucketName)
                    .object(token.toString())
                    .stream(new ByteArrayInputStream(bom), bom.length, -1)
                    .build());
        } catch (Exception e) {
            throw new IOException("Failed to store BOM for token %s".formatted(token), e);
        }
    }

    @Override
    public byte[] getBomByToken(final UUID token) throws IOException {
        try {
            try (final GetObjectResponse response = s3Client.getObject(GetObjectArgs.builder()
                    .bucket(bucketName)
                    .object(token.toString())
                    .build())) {
                return response.readAllBytes();
            }
        } catch (ErrorResponseException e) {
            // https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ErrorCodeList
            if ("NoSuchKey".equalsIgnoreCase(e.errorResponse().code())) {
                return null;
            }

            throw new IOException("Failed to get BOM for token %s".formatted(token), e);
        } catch (Exception e) {
            throw new IOException("Failed to get BOM for token %s".formatted(token), e);
        }
    }

    @Override
    public boolean deleteBomByToken(final UUID token) throws IOException {
        try {
            s3Client.removeObject(RemoveObjectArgs.builder()
                    .bucket(bucketName)
                    .object(token.toString())
                    .build());
        } catch (Exception e) {
            throw new IOException("Failed to delete BOM for token %s".formatted(token), e);
        }

        // NB: S3 doesn't return any indication or error if the object
        // to be deleted did not exist. We have to assume that if the
        // request succeeded, it has successfully deleted the object.
        return true;
    }

    @Override
    public int deleteBomsForRetentionDuration(final Duration duration) {
        LOGGER.info("Not deleting any BOMs; Retention is managed via bucket retention policy");
        return 0;
    }

}
