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

public interface FileStorage extends ExtensionPoint {

    FileMetadata store(final String name, final byte[] content) throws IOException;

    byte[] get(final String key) throws IOException;

    boolean delete(final String key) throws IOException;

    // TODO: deleteMany. Some remote storage backends support batch deletes.
    //  https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html

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
