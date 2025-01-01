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

import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;

import java.io.IOException;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public interface FileStorage extends ExtensionPoint {

    Pattern VALID_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_\\-.]+");

    FileMetadata store(final String name, final byte[] content) throws IOException;

    byte[] get(final FileMetadata fileMetadata) throws IOException;

    boolean delete(final FileMetadata fileMetadata) throws IOException;

    // TODO: deleteMany. Some remote storage backends support batch deletes.
    //  https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html

    static void requireValidName(final String name) {
        requireNonNull(name, "name must not be null");

        if (!VALID_NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException("name must match pattern: " + VALID_NAME_PATTERN.pattern());
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
