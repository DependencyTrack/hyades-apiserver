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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.RoleDao;

import alpine.common.logging.Logger;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.UserPrincipal;
import alpine.resources.AlpineRequest;

final class RoleQueryManager extends QueryManager implements IQueryManager {

    /**
     * Represents a row returned by the USER_PROJECT_EFFECTIVE_PERMISSIONS view.
     *
     * @since 5.6.0
     */
    public record UserProjectEffectivePermissionsRow(
            Long ldapUserId,
            Long managedUserId,
            Long oidcUserId,
            Long projectId,
            Long permissionId,
            String permissionName) {
    }

    private static final Logger LOGGER = Logger.getLogger(RoleQueryManager.class);

    RoleQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    RoleQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    @Override
    public Role createRole(final String name, final List<Permission> permissions) {
        return callInTransaction(() -> {
            final Role role = new Role();
            role.setName(name);
            role.setPermissions(Set.copyOf(permissions));

            return persist(role);
        });
    }

    @Override
    public List<Role> getRoles() {
        final Query<Role> query = pm.newQuery(Role.class);
        if (orderBy == null)
            query.setOrdering("name asc");

        return query.executeList();
    }

    @Override
    public Role getRole(final String uuid) {
        return getObjectByUuid(Role.class, uuid, Role.FetchGroup.ALL.name());
    }

    @Override
    public List<? extends ProjectRole> getUserRoles(final UserPrincipal user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class)
                .getUserRoles(user.getClass(), user.getUsername()));
    }

    public List<Project> getUnassignedProjects(final String username) {
        return getUnassignedProjects(getUserPrincipal(username));
    }

    public List<Project> getUnassignedProjects(final UserPrincipal user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).getUserUnassignedProjects(
                user.getClass(),
                user.getUsername()));
    }

    public List<Permission> getUnassignedRolePermissions(final Role role) {
        final List<Permission> permissions = new ArrayList<>();

        final var permissionNames = role.getPermissions().stream()
                .map(Permission::getName)
                .toList();

        final Query<Permission> query = pm.newQuery(Permission.class)
                .filter("!:permissionNames.contains(name)")
                .setNamedParameters(Map.of("permissionNames", permissionNames));

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
    public List<Permission> getUserProjectPermissions(final String username, final String projectName) {
        final UserPrincipal user = getUserPrincipal(username);
        final String columnName;

        switch (user) {
            case LdapUser ldapUser -> columnName = "LDAPUSER_ID";
            case ManagedUser managedUser -> columnName = "MANAGEDUSER_ID";
            case OidcUser oidcUser -> columnName = "OIDCUSER_ID";
            default -> {
                return null;
            }
        }

        final Query<Project> projectsQuery = pm.newQuery(Project.class)
                .filter("name == :projectName")
                .setNamedParameters(Map.of("projectName", projectName));

        final String projectIds = executeAndCloseList(projectsQuery).stream()
                .map(Project::getId)
                .map(String::valueOf)
                .collect(Collectors.joining(", ", "'{", "}'"));

        // language=SQL
        final var queryString = """
                SELECT
                    upep."LDAPUSER_ID",
                    upep."MANAGEDUSER_ID",
                    upep."OIDCUSER_ID",
                    upep."PROJECT_ID",
                    upep."PERMISSION_ID",
                    upep."PERMISSION_NAME"
                  FROM "USER_PROJECT_EFFECTIVE_PERMISSIONS" upep
                 WHERE upep."%s" = :userId
                   AND upep."PROJECT_ID" = ANY(%s)
                """.formatted(columnName, projectIds);

        final Query<?> query = pm.newQuery(Query.SQL, queryString);
        query.setNamedParameters(Map.of(
                "userId", user.getId(),
                "projectIds", projectIds));

        return executeAndCloseResultList(query, UserProjectEffectivePermissionsRow.class)
                .stream()
                .map(UserProjectEffectivePermissionsRow::permissionName)
                .map(this::getPermission)
                .distinct()
                .toList();
    }

    @Override
    public boolean addRoleToUser(final UserPrincipal user, final Role role, final Project project) {
        return JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        user.getClass(),
                        user.getId(),
                        project.getId(),
                        role.getId())) == 1;
    }

    @Override
    public boolean removeRoleFromUser(final UserPrincipal user, final Role role, final Project project) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).removeRoleFromUser(
                user.getClass(),
                user.getId(),
                project.getName(),
                role.getId())) > 0;
    }

}
