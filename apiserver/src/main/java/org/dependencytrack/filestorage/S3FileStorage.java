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

import com.github.luben.zstd.Zstd;
import io.minio.GetObjectArgs;
import io.minio.GetObjectResponse;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import io.minio.errors.ErrorResponseException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.utils.URIBuilder;
import org.dependencytrack.spi.filestorage.FileMetadata;
import org.dependencytrack.spi.filestorage.FileStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.NoSuchFileException;
import java.util.Arrays;
import java.util.HexFormat;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.spi.filestorage.FileStorage.requireValidFileName;

/**
 * @since 5.6.0
 */
final class S3FileStorage implements FileStorage {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3FileStorage.class);
    static final String EXTENSION_NAME = "s3";

    private final MinioClient s3Client;
    private final String bucketName;
    private final int compressionThresholdBytes;
    private final int compressionLevel;

    S3FileStorage(
            final MinioClient s3Client,
            final String bucketName,
            final int compressionThresholdBytes,
            final int compressionLevel) {
        this.s3Client = s3Client;
        this.bucketName = bucketName;
        this.compressionThresholdBytes = compressionThresholdBytes;
        this.compressionLevel = compressionLevel;
    }

    private record S3FileLocation(String bucket, String object) {

        private static S3FileLocation from(final FileMetadata fileMetadata) {
            if (!EXTENSION_NAME.equals(fileMetadata.location().getScheme())) {
                throw new IllegalArgumentException("%s: Unexpected scheme %s, expected %s".formatted(
                        fileMetadata.location(), fileMetadata.location().getScheme(), EXTENSION_NAME));
            }
            if (fileMetadata.location().getHost() == null) {
                throw new IllegalArgumentException(
                        "Host portion of URI %s not set Unable to determine bucket".formatted(fileMetadata.location()));
            }
            if (fileMetadata.location().getPath() == null) {
                throw new IllegalArgumentException(
                        "Path portion of URI %s not set; Unable to determine object name".formatted(fileMetadata.location()));
            }

            // The value returned by URI#getPath always has a leading slash.
            // Remove it to prevent the path from erroneously be interpreted as absolute.
            return new S3FileLocation(fileMetadata.location().getHost(), fileMetadata.location().getPath().replaceFirst("^/", ""));
        }

        private URI asURI() {
            try {
                return new URIBuilder()
                        .setScheme(EXTENSION_NAME)
                        .setHost(bucket)
                        .setPath(object)
                        .build();
            } catch (URISyntaxException e) {
                throw new IllegalStateException("Failed to build URI for " + this, e);
            }
        }

    }

    @Override
    public FileMetadata store(final String fileName, final String mediaType, final byte[] content) throws IOException {
        requireValidFileName(fileName);
        requireNonNull(content, "content must not be null");

        final var fileLocation = new S3FileLocation(bucketName, fileName);
        final URI locationUri = fileLocation.asURI();

        final byte[] maybeCompressedContent = content.length >= compressionThresholdBytes
                ? Zstd.compress(content, compressionLevel)
                : content;

        final byte[] contentDigest = DigestUtils.sha256(maybeCompressedContent);

        try {
            s3Client.putObject(PutObjectArgs.builder()
                    .bucket(fileLocation.bucket())
                    .object(fileLocation.object())
                    .stream(new ByteArrayInputStream(maybeCompressedContent), maybeCompressedContent.length, -1)
                    .build());
        } catch (Exception e) {
            if (e instanceof final IOException ioe) {
                throw ioe;
            }

            throw new IOException(e);
        }

        return new FileMetadata(locationUri, mediaType, contentDigest, null);
    }

    @Override
    public byte[] get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final var fileLocation = S3FileLocation.from(fileMetadata);

        final byte[] maybeCompressedContent;
        try {
            try (final GetObjectResponse response = s3Client.getObject(
                    GetObjectArgs.builder()
                            .bucket(fileLocation.bucket())
                            .object(fileLocation.object())
                            .build())) {
                maybeCompressedContent = response.readAllBytes();
            }
        } catch (ErrorResponseException e) {
            // https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ErrorCodeList
            if ("NoSuchKey".equalsIgnoreCase(e.errorResponse().code())) {
                throw new NoSuchFileException(fileMetadata.location().toString());
            }

            throw new IOException("Failed to get file %s".formatted(fileMetadata.location()), e);
        } catch (Exception e) {
            if (e instanceof final IOException ioe) {
                throw ioe;
            }

            throw new IOException(e);
        }

        final byte[] actualContentDigest = DigestUtils.sha256(maybeCompressedContent);
        final byte[] expectedContentDigest = fileMetadata.sha256Digest();

        if (!Arrays.equals(actualContentDigest, expectedContentDigest)) {
            throw new IOException("SHA256 digest mismatch: actual=%s, expected=%s".formatted(
                    HexFormat.of().formatHex(actualContentDigest), HexFormat.of().formatHex(fileMetadata.sha256Digest())));
        }

        final long decompressedSize = Zstd.decompressedSize(maybeCompressedContent);
        if (Zstd.decompressedSize(maybeCompressedContent) <= 0) {
            return maybeCompressedContent; // Not compressed.
        }

        return Zstd.decompress(maybeCompressedContent, Math.toIntExact(decompressedSize));
    }

    @Override
    public boolean delete(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final var fileLocation = S3FileLocation.from(fileMetadata);

        try {
            s3Client.removeObject(RemoveObjectArgs.builder()
                    .bucket(fileLocation.bucket())
                    .object(fileLocation.object())
                    .build());
        } catch (Exception e) {
            if (e instanceof final IOException ioe) {
                throw ioe;
            }

            throw new IOException(e);
        }

        // S3 doesn't return any indication or error if the object
        // to be deleted did not exist. We have to assume that if the
        // request succeeded, it has successfully deleted the object.
        return true;
    }

}
