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

import org.dependencytrack.api.v2.model.ExternalReference;
import org.dependencytrack.api.v2.model.License;
import org.dependencytrack.api.v2.model.OrganizationalContact;
import org.dependencytrack.api.v2.model.OrganizationalEntity;

import java.util.Arrays;
import java.util.List;

public class ModelMapper {

    public static OrganizationalEntity mapOrganizationEntity(org.dependencytrack.model.OrganizationalEntity entity) {
        if (entity == null) {
            return null;
        }
        var builder = OrganizationalEntity.builder()
                .name(entity.getName());
        if (entity.getUrls() != null) {
            builder.urls(Arrays.stream(entity.getUrls()).toList());
        }
        if (entity.getUrls().length > 0) {
            builder.contacts(mapOrganizationContacts(entity.getContacts()));
        }
        return builder.build();
    }

    public static List<OrganizationalContact> mapOrganizationContacts(List<org.dependencytrack.model.OrganizationalContact> contacts) {
        if (contacts == null) {
            return List.of();
        }
        return contacts.stream()
                .<OrganizationalContact>map(authorRow -> OrganizationalContact.builder()
                        .name(authorRow.getName())
                        .email(authorRow.getEmail())
                        .phone(authorRow.getPhone())
                        .build()).toList();
    }

    public static List<ExternalReference> mapExternalReferences(List<org.dependencytrack.model.ExternalReference> externalReferences) {
        return externalReferences.stream()
                .<ExternalReference>map(externalReference -> ExternalReference.builder()
                        .type(ExternalReference.TypeEnum.valueOf(externalReference.getType().name()))
                        .comment(externalReference.getComment())
                        .url(externalReference.getUrl())
                        .build()).toList();
    }

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
}
