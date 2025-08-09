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

import org.dependencytrack.api.v2.model.OrganizationalContact;

import java.util.List;

public class ModelMapper {

    public static List<org.dependencytrack.model.OrganizationalContact> mapOrganizationalContacts(final List<OrganizationalContact> contacts) {
        return contacts.stream()
                .map(contact -> {
                    var mappedContact = new org.dependencytrack.model.OrganizationalContact();
                    mappedContact.setName(contact.getName());
                    mappedContact.setEmail(contact.getEmail());
                    mappedContact.setPhone(contact.getPhone());
                    return mappedContact;
                }).toList();
    }
}
