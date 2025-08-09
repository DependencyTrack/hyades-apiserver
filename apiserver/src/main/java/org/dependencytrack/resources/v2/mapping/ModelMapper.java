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
package org.dependencytrack.resources.v2.mapping;

import org.dependencytrack.api.v2.model.Hashes;
import org.dependencytrack.api.v2.model.License;
import org.dependencytrack.model.Component;

public class ModelMapper {

    public static License mapLicense(org.dependencytrack.model.License license) {
        if (license == null) {
            return null;
        }
        return License.builder()
                .name(license.getName())
                .customLicense(license.isCustomLicense())
                .fsfLibre(license.isFsfLibre())
                .licenseId(license.getLicenseId())
                .osiApproved(license.isOsiApproved())
                .uuid(license.getUuid())
                .build();
    }

    public static Hashes mapHashes(Component component) {
        boolean hasAnyHash = component.getMd5() != null
                || component.getSha1() != null
                || component.getSha256() != null
                || component.getSha384() != null
                || component.getSha512() != null
                || component.getSha3_256() != null
                || component.getSha3_384() != null
                || component.getSha3_512() != null
                || component.getBlake2b_256() != null
                || component.getBlake2b_384() != null
                || component.getBlake2b_512() != null
                || component.getBlake3() != null;

        if (!hasAnyHash) {
            return null;
        }

        return Hashes.builder()
                .md5(component.getMd5())
                .sha1(component.getSha1())
                .sha256(component.getSha256())
                .sha384(component.getSha384())
                .sha512(component.getSha512())
                .sha3256(component.getSha3_256())
                .sha3384(component.getSha3_384())
                .sha3512(component.getSha3_512())
                .blake2b256(component.getBlake2b_256())
                .blake2b384(component.getBlake2b_384())
                .blake2b512(component.getBlake2b_512())
                .blake3(component.getBlake3())
                .build();
    }
}
