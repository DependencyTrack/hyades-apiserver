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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.SecretsApi;
import org.dependencytrack.api.v2.model.CreateSecretRequest;
import org.dependencytrack.api.v2.model.ListSecretsResponse;
import org.dependencytrack.api.v2.model.ListSecretsResponseItem;
import org.dependencytrack.api.v2.model.UpdateSecretRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.secret.management.SecretAlreadyExistsException;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.secret.management.SecretMetadata;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

@Path("/")
public class SecretsResource implements SecretsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecretsResource.class);

    @Inject
    private SecretManager secretManager;

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_CREATE
    })
    public Response createSecret(final CreateSecretRequest request) {
        try {
            secretManager.createSecret(
                    request.getName(),
                    request.getDescription(),
                    request.getValue());
        } catch (SecretAlreadyExistsException e) {
            throw new AlreadyExistsException(e.getMessage(), e);
        } catch (UnsupportedOperationException e) {
            throw new BadRequestException(e.getMessage(), e);
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Created secret: {}", request.getName());
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_UPDATE
    })
    public Response updateSecret(final String name, final UpdateSecretRequest request) {
        final boolean updated;
        try {
            updated = secretManager.updateSecret(
                    name,
                    request.getDescription(),
                    request.getValue());
        } catch (UnsupportedOperationException e) {
            throw new BadRequestException(e.getMessage(), e);
        }
        if (!updated) {
            return Response.notModified().build();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Updated secret: {}", name);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_DELETE
    })
    public Response deleteSecret(final String name) {
        try {
            secretManager.deleteSecret(name);
        } catch (UnsupportedOperationException e) {
            throw new BadRequestException(e.getMessage(), e);
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Deleted secret: {}", name);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SECRET_MANAGEMENT,
            Permissions.Constants.SECRET_MANAGEMENT_READ
    })
    public Response listSecrets() {
        final List<SecretMetadata> secrets = secretManager.listSecrets();

        final var responseItems = new ArrayList<ListSecretsResponseItem>(secrets.size());

        for (final SecretMetadata secret : secrets) {
            responseItems.add(
                    ListSecretsResponseItem.builder()
                            .name(secret.name())
                            .description(secret.description())
                            .createdAt(secret.createdAt() != null
                                    ? secret.createdAt().toEpochMilli()
                                    : null)
                            .updatedAt(secret.updatedAt() != null
                                    ? secret.updatedAt().toEpochMilli()
                                    : null)
                            .build());
        }

        final var response = ListSecretsResponse.builder()
                .secrets(responseItems)
                .build();

        return Response.ok(response).build();
    }

}
