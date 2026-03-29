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
import alpine.persistence.AlpineQueryManager;
import alpine.server.auth.PermissionRequired;
import jakarta.annotation.Priority;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.owasp.security.logging.SecurityMarkers;

import javax.jdo.Query;
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
    static final String ACL_ENABLED_GROUP_NAME = "access-management";
    static final String ACL_ENABLED_PROPERTY_NAME = "acl.enabled";

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        final Principal principal = (Principal) requestContext.getProperty("Principal");
        if (principal == null) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_FAILURE,
                    "A request was made without the assertion of a valid user principal");
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
        }

        final Set<String> effectivePermissions;
        final Set<String> requiredPermissions = getRequiredPermissions();
        final boolean isProjectAccessFiltered = resourceInfo
                .getResourceMethod()
                .isAnnotationPresent(ProjectAccessFiltered.class);

        try (final var qm = new AlpineQueryManager()) {
            effectivePermissions = qm.getEffectivePermissions(principal);
            final boolean hasGlobalPermission = requiredPermissions.isEmpty()
                    || !Collections.disjoint(requiredPermissions, effectivePermissions);

            if (!hasGlobalPermission) {
                // Principal may have the required permission(s) only for a subset of
                // projects. Downstream resources will enforce ACLs fully, but we can
                // still short-circuit when the permission(s) is not assigned for any
                // project at all.
                final boolean hasProjectPermission = isProjectAccessFiltered
                        && isAclEnabled(qm)
                        && qm.hasAnyProjectPermission(principal, requiredPermissions);
                if (!hasProjectPermission) {
                    logUnauthorizedAccess();
                    throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
                }
            }
        }

        requestContext.setProperty(EFFECTIVE_PERMISSIONS_PROPERTY, effectivePermissions);
    }

    private Set<String> getRequiredPermissions() {
        final var annotation = resourceInfo
                .getResourceMethod()
                .getDeclaredAnnotation(PermissionRequired.class);
        return annotation != null
                ? Set.of(annotation.value())
                : Set.of();
    }

    private static boolean isAclEnabled(AlpineQueryManager qm) {
        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, /* language=SQL */ """
                SELECT EXISTS(
                  SELECT 1
                    FROM "CONFIGPROPERTY"
                   WHERE "GROUPNAME" = ?
                     AND "PROPERTYNAME" = ?
                     AND "PROPERTYVALUE" = 'true'
                )
                """);
        query.setParameters(ACL_ENABLED_GROUP_NAME, ACL_ENABLED_PROPERTY_NAME);
        try {
            return query.executeResultUnique(Boolean.class);
        } finally {
            query.closeAll();
        }
    }

    private void logUnauthorizedAccess() {
        // NB: Principal and request URI are already in MDC so will be included in logs.
        LOGGER.info(SecurityMarkers.SECURITY_FAILURE, "Unauthorized access attempt");
    }

}
