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
package org.dependencytrack.provisioning.config;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

/**
 * @since 5.7.0
 */
public sealed interface ProvisioningResource {

    record ExtensionConfigResource(
            @JsonProperty("extension_point") String extensionPointName,
            @JsonProperty("extension") String extensionName,
            String config) implements ProvisioningResource {
    }

    record SecretResource(
            String name,
            String description,
            String value) implements ProvisioningResource {
    }

    record TeamResource(
            String name,
            @JsonProperty("permissions") Set<String> permissionNames) implements ProvisioningResource {
    }

    record UserResource(
            String name,
            String email,
            String password,
            @JsonProperty("teams") Set<String> teamNames) implements ProvisioningResource {
    }

}
