/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.filters;

import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.User;
import alpine.persistence.AlpineQueryManager;
import alpine.server.auth.PermissionRequired;
import org.owasp.security.logging.SecurityMarkers;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;

/**
 * A filter that ensures that all principals making calls that are going
 * through this filter have the necessary permissions to do so.
 *
 * @author Steve Springett
 * @see AuthorizationFeature
 * @since 1.0.0
 */
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(AuthorizationFilter.class);

    public static final String EFFECTIVE_PERMISSIONS_PROPERTY = "effectivePermissions";
    public static final String ACL_ENABLED_GROUP_NAME = "access-management";
    public static final String ACL_ENABLED_PROPERTY_NAME = "acl.enabled";

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        final Principal principal = (Principal) requestContext.getProperty("Principal");
        if (principal == null) {
            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "A request was made without the assertion of a valid user principal");
            requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
            return;
        }

        final Set<String> effectivePermissions;
        final boolean isAclEnabled;

        try (final var qm = new AlpineQueryManager()) {
            effectivePermissions = qm.getEffectivePermissions(principal);
            final ConfigProperty property = qm.getConfigProperty(ACL_ENABLED_GROUP_NAME, ACL_ENABLED_PROPERTY_NAME);
            isAclEnabled = property != null && "true".equals(property.getPropertyValue());
        }

        if (isAclEnabled && resourceInfo.getResourceMethod().isAnnotationPresent(ResourceAccessRequired.class)) {
            requestContext.setProperty(EFFECTIVE_PERMISSIONS_PROPERTY, effectivePermissions);
            return;
        }

        final PermissionRequired annotation = resourceInfo.getResourceMethod().getDeclaredAnnotation(PermissionRequired.class);
        final Set<String> permissions = Set.of(annotation.value());

        final boolean hasNoRequiredPermission = Collections.disjoint(permissions, effectivePermissions);
        if (hasNoRequiredPermission) {
            final String requestUri = requestContext.getUriInfo().getRequestUri().toString();
            final String requestPrincipal;

            switch (principal) {
                case ApiKey apiKey -> requestPrincipal = "API Key " + apiKey.getMaskedKey();
                case User user -> requestPrincipal = user.getUsername();
                default -> throw new IllegalStateException("Unexpected principal type: " + principal.getClass().getName());
            }

            LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Unauthorized access attempt made by %s to %s"
                    .formatted(requestPrincipal, requestUri));

            requestContext.abortWith(Response.status(Response.Status.FORBIDDEN).build());
        } else {
            requestContext.setProperty(EFFECTIVE_PERMISSIONS_PROPERTY, effectivePermissions);
        }
    }

}
