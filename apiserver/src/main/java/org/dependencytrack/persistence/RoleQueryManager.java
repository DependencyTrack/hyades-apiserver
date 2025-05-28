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

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.ProjectRoleBinding;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.RoleDao;

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
        return callInTransaction(() -> {
            final Role role = new Role();
            role.setName(name);
            role.setPermissions(Set.copyOf(permissions));

            LOGGER.debug(name + " role created with permissions: "
                    + String.join(", ", permissions.stream().map(Permission::getName).toList()));

            return persist(role);
        });
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
                .setNamedParameters(Map.of("name", role))
                .range(0, 1);

        return executeAndCloseUnique(query);
    }

    @Override
    public Role getRole(final String uuid) {
        return getObjectByUuid(Role.class, uuid, Role.FetchGroup.ALL.name());
    }

    @Override
    public List<ProjectRoleBinding> getUserRoles(final User user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class)
                .getUserRoles(user.getUsername()));
    }

    public List<Project> getUnassignedProjects(final String username) {
        return getUnassignedProjects(getUser(username));
    }

    public List<Project> getUnassignedProjects(final User user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class)
                .getUserUnassignedProjects(user.getUsername()));
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
    public boolean addRoleToUser(final User user, final Role role, final Project project) {
        return JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(
                        user.getId(),
                        project.getId(),
                        role.getId())) == 1;
    }

    @Override
    public boolean removeRoleFromUser(final User user, final Role role, final Project project) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).removeRoleFromUser(
                user.getId(),
                project.getName(),
                role.getId())) > 0;
    }

}
