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

import java.util.List;
import java.util.stream.Collectors;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

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
        Role role = new Role();
        role.setName(name);
        role.getPermissions().addAll(getPermissionsByName(
                permissions.stream()
                        .map(Permission::getName)
                        .toList()));

        LOGGER.debug("%s role created with permissions: %s".formatted(
                name, permissions.stream().map(Permission::getName).collect(Collectors.joining(", "))));

        return persist(role);
    }

    @Override
    public boolean addPermissionToRole(final Role role, final Permission permission) {
        final Query<Permission> query = pm.newQuery(Permission.class)
                .variables("org.dependencytrack.model.Role role")
                .filter("role.id == :roleId && role.permissions.contains(this) && this.id == :permissionId")
                .setParameters(role.getId(), permission.getId())
                .result("count(this) > 0");

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
    public List<UserProjectRole> getUserRoles(final String username) {
        final Query<UserProjectRole> query = pm.newQuery(UserProjectRole.class)
                .filter("user.username == :username")
                .setParameters(username);

        return executeAndCloseList(query);
    }

    public List<Project> getUnassignedProjects(final String username) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=sql */ """
                SELECT p."ID", p."NAME", p."VERSION", p."UUID"
                  FROM "PROJECT" p
                 WHERE NOT EXISTS (
                   SELECT 1
                     FROM "USER_PROJECT_ROLES" upr
                    INNER JOIN "USER" u
                       ON u."ID" = upr."USER_ID"
                    WHERE upr."PROJECT_ID" = p."ID"
                      AND u."USERNAME" = ?
                 )
                """)
                .setParameters(username);

        return executeAndCloseResultList(query, Project.class);
    }

    public List<Permission> getUnassignedRolePermissions(final Role role) {
        final Query<Permission> query = pm.newQuery(Permission.class)
                .filter("role.id == :roleId && !role.permissions.contains(this)")
                .variables("org.dependencytrack.model.Role role")
                .setParameters(role.getId());

        return executeAndCloseList(query);
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
        final Query<UserProjectRole> query = pm.newQuery(UserProjectRole.class)
                .filter("user.id == :userId && project.id == :projectId")
                .setParameters(user.getId(), project.getId());

        final UserProjectRole existingRole = executeAndCloseUnique(query);

        if (existingRole != null) {
            return handleExistingRole(user, role, project, existingRole);
        }

        persist(new UserProjectRole(user, project, role));
        return true;
    }

    private boolean handleExistingRole(final User user, final Role role, final Project project, final UserProjectRole existingRole) {
        if (existingRole.getRole().getId() == role.getId()) {
            LOGGER.debug("User '%s' already has role '%s' on project '%s', no action taken.".formatted(
                    user.getUsername(), role.getName(), project.getName()));
            return false;
        }
        existingRole.setRole(role);
        persist(existingRole);
        return true;
    }

    @Override
    public boolean removeRoleFromUser(final User user, final Role role, final Project project) {
        final Query<UserProjectRole> query = pm.newQuery(UserProjectRole.class)
                .filter("user.id == :userId && project.id == :projectId && role.id == :roleId")
                .setParameters(user.getId(), project.getId(), role.getId());

        final UserProjectRole projectRole = executeAndCloseUnique(query);

        if (projectRole == null)
            return false;

        delete(projectRole);

        return true;
    }

    @Override
    public boolean userProjectRoleExists(final User user, final Role role, final Project project) {
        final Query<UserProjectRole> query = pm.newQuery(UserProjectRole.class)
                .filter("user.id == :userId && project.id == :projectId && role.id == :roleId")
                .setParameters(user.getId(), project.getId(), role.getId())
                .result("count(this) > 0");

        return executeAndCloseResultUnique(query, Boolean.class);
    }

}
