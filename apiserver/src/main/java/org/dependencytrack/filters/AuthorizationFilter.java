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
package org.dependencytrack.filters;

import alpine.common.logging.Logger;
import alpine.server.auth.DisableAuthorization;

import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.server.ContainerRequest;
import org.owasp.security.logging.SecurityMarkers;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import java.security.Principal;

/**
 * A filter that ensures that all principals making calls that are going
 * through this filter have the necessary permissions to do so.
 *
 * @author Jonathan Howard
 * @see AuthorizationFeature
 * @since 5.6.0
 */
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(AuthorizationFilter.class);

    public static final String EFFECTIVE_PERMISSIONS_PROPERTY = "effectivePermissions";

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (!(requestContext instanceof ContainerRequest)
                || resourceInfo.getResourceMethod().getDeclaredAnnotation(DisableAuthorization.class) == null)
            return;

        final Principal principal = (Principal) requestContext.getProperty("Principal");
        if (principal == null) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "A request was made without the assertion of a valid user principal");
            requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
            return;
        }

        try (final var qm = new QueryManager()) {
            requestContext.setProperty(EFFECTIVE_PERMISSIONS_PROPERTY, qm.getEffectivePermissions(principal));
        }

    }

}
