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

import com.github.luben.zstd.ZstdInputStream;
import com.github.luben.zstd.ZstdOutputStream;
import io.minio.GetObjectArgs;
import io.minio.GetObjectResponse;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import io.minio.errors.ErrorResponseException;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;

import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.NoSuchFileException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.filestorage.api.FileStorage.requireValidFileName;

/**
 * @since 5.6.0
 */
final class S3FileStorage implements FileStorage {

    static final String EXTENSION_NAME = "s3";

    private final MinioClient s3Client;
    private final String bucketName;
    private final int compressionLevel;

    S3FileStorage(
            final MinioClient s3Client,
            final String bucketName,
            final int compressionLevel) {
        this.s3Client = s3Client;
        this.bucketName = bucketName;
        this.compressionLevel = compressionLevel;
    }

    private record S3FileLocation(String bucket, String object) {

        private static S3FileLocation from(final FileMetadata fileMetadata) {
            final URI locationUri = URI.create(fileMetadata.getLocation());
            if (!EXTENSION_NAME.equals(locationUri.getScheme())) {
                throw new IllegalArgumentException("%s: Unexpected scheme %s, expected %s".formatted(
                        locationUri, locationUri.getScheme(), EXTENSION_NAME));
            }
            if (locationUri.getHost() == null) {
                throw new IllegalArgumentException(
                        "Host portion of URI %s not set Unable to determine bucket".formatted(locationUri));
            }
            if (locationUri.getPath() == null) {
                throw new IllegalArgumentException(
                        "Path portion of URI %s not set; Unable to determine object name".formatted(locationUri));
            }

            // The value returned by URI#getPath always has a leading slash.
            // Remove it to prevent the path from erroneously be interpreted as absolute.
            return new S3FileLocation(locationUri.getHost(), locationUri.getPath().replaceFirst("^/", ""));
        }

        private URI asURI() {
            return URI.create("%s://%s/%s".formatted(EXTENSION_NAME, bucket, object));
        }

    }

    @Override
    public FileMetadata store(final String fileName, final String mediaType, final InputStream contentStream) throws IOException {
        requireValidFileName(fileName);
        requireNonNull(contentStream, "contentStream must not be null");

        final var fileLocation = new S3FileLocation(bucketName, fileName);
        final URI locationUri = fileLocation.asURI();

        final MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        final var pipedOutputStream = new PipedOutputStream();
        final var pipedInputStream = new PipedInputStream(pipedOutputStream, 65536 /* (64KiB) */);

        // Transparently compress in a separate thread so reading the entire contentStream can be avoided.
        final var compressionFuture = CompletableFuture.runAsync(() -> {
            try (final var digestOutputStream = new DigestOutputStream(pipedOutputStream, messageDigest);
                 final var zstdOutputStream = new ZstdOutputStream(digestOutputStream, compressionLevel)) {
                contentStream.transferTo(zstdOutputStream);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });

        try {
            s3Client.putObject(PutObjectArgs.builder()
                    .bucket(fileLocation.bucket())
                    .object(fileLocation.object())
                    .stream(
                            pipedInputStream,
                            /* objectSize */ -1,
                            /* partSize */ 10485760 /* (10MiB) */)
                    .build());

            compressionFuture.join();
        } catch (Exception e) {
            compressionFuture.cancel(true);

            if (e instanceof final IOException ioe) {
                throw ioe;
            }

            throw new IOException(e);
        } finally {
            pipedInputStream.close();
        }

        return FileMetadata.newBuilder()
                .setProviderName(EXTENSION_NAME)
                .setLocation(locationUri.toString())
                .setMediaType(mediaType)
                .setSha256Digest(HexFormat.of().formatHex(messageDigest.digest()))
                .build();
    }

    @Override
    public InputStream get(final FileMetadata fileMetadata) throws IOException {
        requireNonNull(fileMetadata, "fileMetadata must not be null");

        final var fileLocation = S3FileLocation.from(fileMetadata);

        final GetObjectResponse response;
        try {
            response = s3Client.getObject(
                    GetObjectArgs.builder()
                            .bucket(fileLocation.bucket())
                            .object(fileLocation.object())
                            .build());
        } catch (ErrorResponseException e) {
            // https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#ErrorCodeList
            if ("NoSuchKey".equalsIgnoreCase(e.errorResponse().code())) {
                throw new NoSuchFileException(fileMetadata.getLocation());
            }

            throw new IOException("Failed to get file %s".formatted(fileMetadata.getLocation()), e);
        } catch (Exception e) {
            if (e instanceof final IOException ioe) {
                throw ioe;
            }

            throw new IOException(e);
        }

        return new ZstdInputStream(response);
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
