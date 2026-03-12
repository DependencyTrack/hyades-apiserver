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
package org.dependencytrack.pkgmetadata.resolution.cargo;

import com.fasterxml.jackson.annotation.JsonFormat;
import org.dependencytrack.pkgmetadata.resolution.api.HashAlgorithm;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.time.format.DateTimeParseException;

@JsonFormat(shape = JsonFormat.Shape.ARRAY)
record CargoCrateVersionMetadata(
        @JsonFormat(shape = JsonFormat.Shape.NUMBER_INT) @Nullable Instant publishedAt,
        @Nullable String sha256) {

    static @Nullable CargoCrateVersionMetadata of(CargoCrateDocument.Version crateVersion) {
        Instant publishedAt = null;
        if (crateVersion.createdAt() != null) {
            try {
                publishedAt = Instant.parse(crateVersion.createdAt());
            } catch (DateTimeParseException ignored) {
            }
        }

        String sha256 = null;
        if (crateVersion.checksum() != null
                && HashAlgorithm.SHA256.isValid(crateVersion.checksum())) {
            sha256 = crateVersion.checksum().toLowerCase();
        }

        if (publishedAt == null && sha256 == null) {
            return null;
        }

        return new CargoCrateVersionMetadata(publishedAt, sha256);
    }

}
