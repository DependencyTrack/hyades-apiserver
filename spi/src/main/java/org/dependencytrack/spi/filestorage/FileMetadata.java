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
package org.dependencytrack.spi.filestorage;

import java.net.URI;
import java.util.Map;

/**
 * Metadata of a stored file.
 *
 * @param location           Location of the file. The URI's scheme is the name of the storage provider.
 *                           Examples: "memory:///foo/bar", "s3://bucket/foo/bar".
 * @param mediaType          Media type of the file.
 * @param sha256Digest       SHA-256 digest of the file content.
 * @param additionalMetadata Additional metadata of the storage provider, i.e. values used for integrity verification.
 * @see <a href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA Media Types</a>
 * @since 5.6.0
 */
public record FileMetadata(
        URI location,
        String mediaType,
        byte[] sha256Digest,
        Map<String, String> additionalMetadata) {
}
