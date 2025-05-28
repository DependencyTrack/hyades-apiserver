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
package org.dependencytrack.persistence;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.datastore.JDOConnection;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.UserProjectRole;

import org.apache.commons.lang3.StringUtils;

import alpine.common.logging.Logger;
import alpine.model.Permission;
import alpine.model.User;
import alpine.resources.AlpineRequest;

final class RoleQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(RoleQueryManager.class);

    RoleQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    RoleQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    @Override
    public Role createRole(final String name, final List<Permission> permissions) {
        final Role role = new Role();
        role.setName(name);
        role.setPermissions(Set.copyOf(permissions));

        LOGGER.debug("%s role created with permissions: %s".formatted(
                name, permissions.stream().map(Permission::getName).collect(Collectors.joining(", "))));

        return persist(role);
    }

    @Override
    public boolean addPermissionToRole(final Role role, final Permission permission) {
        Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT EXISTS(
                  SELECT 1
                    FROM "ROLES_PERMISSIONS"
                   WHERE "ROLE_ID" = ?
                     AND "PERMISSION_ID" = ?
                )
                """)
                .setParameters(role.getId(), permission.getId());

        if (executeAndCloseResultUnique(query, Boolean.class))
            return false;

        role.addPermissions(permission);
        persist(role);

        LOGGER.debug("Permission '%s' added to role '%s'".formatted(permission.getName(), role.getName()));

        return true;
    }

    @Override
    public List<Role> getRoles() {
        final Query<Role> query = pm.newQuery(Role.class);
        if (orderBy == null)
            query.setOrdering("name asc");

        decorate(query);

        return query.executeList();
    }

    @Override
    public Role getRoleByName(final String name) {
        final String role = StringUtils.lowerCase(StringUtils.trimToNull(name));
        final Query<Role> query = pm.newQuery(Role.class)
                .filter("name.toLowerCase().trim() == :name")
                .setParameters(role)
                .range(0, 1);

        return executeAndCloseUnique(query);
    }

    @Override
    public Role getRole(final String uuid) {
        return getObjectByUuid(Role.class, uuid, Role.FetchGroup.ALL.name());
    }

    @Override
    public List<UserProjectRole> getUserRoles(final User user) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT upr."USER_ID", upr."PROJECT_ID", upr."ROLE_ID"
                  FROM "USER_PROJECT_ROLES" upr
                 INNER JOIN "USER" u
                    ON u."ID" = upr."USER_ID"
                 WHERE u."USERNAME" = ?
                """)
                .setParameters(user.getUsername());

        return executeAndCloseResultList(query, UserProjectRole.class);
    }

    public List<Project> getUnassignedProjects(final String username) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT p."ID", p."NAME", p."VERSION", p."UUID"
                  FROM "PROJECT" p
                  LEFT JOIN "USER_PROJECT_ROLES" upr
                    ON upr."PROJECT_ID" = p."ID"
                  LEFT JOIN "USER" u
                    ON u."ID" = upr."USER_ID"
                 WHERE u."USERNAME" != ?
                    OR u."USERNAME" IS NULL
                   """)
                   .setParameters(username);

        return executeAndCloseResultList(query, Project.class);
    }

    public List<Permission> getUnassignedRolePermissions(final Role role) {
        final List<Permission> permissions = new ArrayList<>();

        final var permissionNames = role.getPermissions().stream()
                .map(Permission::getName)
                .toList();

        final Query<Permission> query = pm.newQuery(Permission.class)
                .filter("!:permissionNames.contains(name)")
                .setParameters(permissionNames);

        permissions.addAll(executeAndCloseList(query));

        return permissions;
    }

    @Override
    public Role updateRole(final Role transientRole) {
        final Role role = getObjectByUuid(Role.class, transientRole.getUuid());
        if (role == null)
            return null;

        role.setName(transientRole.getName());

        return persist(role);
    }

    @Override
    public boolean addRoleToUser(final User user, final Role role, final Project project) {
        Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT EXISTS(
                  SELECT 1
                    FROM "USER_PROJECT_ROLES"
                   WHERE "USER_ID" = ?
                     AND "PROJECT_ID" = ?
                     AND "ROLE_ID" = ?
                )
                """)
                .setParameters(user.getId(), project.getId(), role.getId());

        if (executeAndCloseResultUnique(query, Boolean.class))
            return false;

        final JDOConnection jdoConnection = pm.getDataStoreConnection();
        final var nativeConnection = (Connection) jdoConnection.getNativeConnection();

        try (final PreparedStatement ps = nativeConnection.prepareStatement(
                /* language=sql */ """
                INSERT INTO "USER_PROJECT_ROLES"
                    ("USER_ID", "PROJECT_ID", "ROLE_ID")
                VALUES
                    (?, ?, ?)
                """)) {
            ps.setLong(1, user.getId());
            ps.setLong(2, project.getId());
            ps.setLong(3, role.getId());
            ps.execute();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to add role: user='%s' / project='%s' / role='%s'".formatted(
                user.getUsername(), project.toString(), role.getName()), e);
        } finally {
            jdoConnection.close();
        }

        return true;
    }

    @Override
    public boolean removeRoleFromUser(final User user, final Role role, final Project project) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT *
                  FROM "USER_PROJECT_ROLES"
                 WHERE "USER_ID" = ?
                   AND "PROJECT_ID" = ?
                   AND "ROLE_ID" = ?
                """)
                .setParameters(user.getId(), project.getId(), role.getId());

        final UserProjectRole projectRole = executeAndCloseResultUnique(query, UserProjectRole.class);

        if (projectRole == null)
            return false;

        delete(projectRole);

        return true;
    }

    @Override
    public boolean userProjectRoleExists(final User user, final Role role, final Project project) {
        Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT EXISTS(
                  SELECT 1
                    FROM "USER_PROJECT_ROLES"
                   WHERE "USER_ID" = ?
                     AND "PROJECT_ID" = ?
                     AND "ROLE_ID" = ?
                )
                """)
                .setParameters(user.getId(), project.getId(), role.getId());

        return executeAndCloseResultUnique(query, Boolean.class);
    }

}
