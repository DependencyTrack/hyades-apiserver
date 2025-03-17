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

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.RoleDao;

import alpine.common.logging.Logger;
import alpine.model.Permission;
import alpine.model.UserPrincipal;
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
        role.setPermissions(permissions);

        return persist(role);
    }

    @Override
    public List<Role> getRoles() {
        final Query<Role> query = pm.newQuery(Role.class);
        if (orderBy == null)
            query.setOrdering("name asc");

        return query.executeList();
    }

    @Override
    public Role getRole(String uuid) {
        final Query<Role> query = pm.newQuery(Role.class, "uuid == :uuid");

        return query.executeUnique();
    }

    @Override
    public List<? extends ProjectRole> getUserRoles(UserPrincipal user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).getUserRoles(user));
    }

    public List<Project> getUnassignedProjects(final String username) {
        return getUnassignedProjects(getUserPrincipal(username));
    }

    public List<Project> getUnassignedProjects(final UserPrincipal user) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).getUserUnassignedProjects(user));
    }

    public List<Permission> getUnassignedRolePermissions(final Role role) {
        List<Permission> permissions = new ArrayList<>();

        var permissionNames = role.getPermissions().stream()
                .map(Permission::getName)
                .toList();

        Query<Permission> query = pm.newQuery(Permission.class)
                .filter("!:permissionNames.contains(name)")
                .setNamedParameters(Map.of("permissionNames", permissionNames));

        permissions.addAll(executeAndCloseList(query));

        return permissions;
    }

    @Override
    public Role updateRole(Role transientRole) {
        final Role role = getObjectByUuid(Role.class, transientRole.getUuid());
        if (role == null)
            return null;

        role.setName(transientRole.getName());

        return persist(role);
    }

    @Override
    public boolean addRoleToUser(UserPrincipal user, Role role, Project project) {
        return JdbiFactory.withJdbiHandle(
                handle -> handle.attach(RoleDao.class).addRoleToUser(user, project.getId(), role.getId())) == 1;
    }

    @Override
    public boolean removeRoleFromUser(UserPrincipal user, Role role, Project project) {
        return JdbiFactory.withJdbiHandle(handle -> handle.attach(RoleDao.class).removeRoleFromUser(user,
                project, role.getId())) > 0;

    }

}
