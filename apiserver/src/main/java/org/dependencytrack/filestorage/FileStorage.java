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

import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.6.0
 */
public interface FileStorage extends ExtensionPoint {

    Pattern VALID_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_/\\-.]+");

    /**
     * Persist data to a file in storage.
     * <p>
     * Storage providers may transparently perform additional steps,
     * such as encryption and compression.
     *
     * @param fileName  Name of the file. This fileName is not guaranteed to be reflected
     *                  in storage as-is. It may be modified or changed entirely.
     * @param mediaType Media type of the file.
     * @param content   Data to store.
     * @return Metadata of the stored file.
     * @throws IOException When storing the file failed.
     * @see <a href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA Media Types</a>
     */
    FileMetadata store(final String fileName, final String mediaType, final byte[] content) throws IOException;

    /**
     * Persist data to a file in storage, assuming the media type to be {@code application/octet-stream}.
     *
     * @see #store(String, String, byte[])
     */
    default FileMetadata store(final String fileName, final byte[] content) throws IOException {
        return store(fileName, "application/octet-stream", content);
    }

    /**
     * Retrieves a file from storage.
     * <p>
     * Storage providers may transparently perform additional steps,
     * such as integrity verification, decryption and decompression.
     * <p>
     * Trying to retrieve a file from a different storage provider
     * is an illegal operation and yields an exception.
     *
     * @param fileMetadata Metadata of the file to retrieve.
     * @return The file's content.
     * @throws IOException           When retrieving the file failed.
     * @throws FileNotFoundException When the requested file was not found.
     */
    byte[] get(final FileMetadata fileMetadata) throws IOException;

    /**
     * Deletes a file from storage.
     * <p>
     * Trying to delete a file from a different storage provider
     * is an illegal operation and yields an exception.
     *
     * @param fileMetadata Metadata of the file to delete.
     * @return {@code true} when the file was deleted, otherwise {@code false}.
     * @throws IOException When deleting the file failed.
     */
    boolean delete(final FileMetadata fileMetadata) throws IOException;

    // TODO: deleteMany. Some remote storage backends support batch deletes.
    //  https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html

    static void requireValidFileName(final String fileName) {
        requireNonNull(fileName, "fileName must not be null");

        if (!VALID_NAME_PATTERN.matcher(fileName).matches()) {
            throw new IllegalArgumentException("fileName must match pattern: " + VALID_NAME_PATTERN.pattern());
        }
    }

    class ExtensionPointMetadata implements org.dependencytrack.plugin.api.ExtensionPointMetadata<FileStorage> {

        @Override
        public String name() {
            return "file.storage";
        }

        @Override
        public boolean required() {
            return true;
        }

        @Override
        public Class<FileStorage> extensionPointClass() {
            return FileStorage.class;
        }

    }

}
