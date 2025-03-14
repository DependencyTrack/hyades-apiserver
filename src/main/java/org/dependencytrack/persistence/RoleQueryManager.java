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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import org.dependencytrack.model.MappedRole;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Role;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.RoleDao;
import org.jdbi.v3.core.Handle;

import alpine.common.logging.Logger;
import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.UserPrincipal;
import alpine.resources.AlpineRequest;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

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
    public List<MappedRole> getUserRoles(UserPrincipal user) {
        String usersField;

        switch (user) {
            case LdapUser ldapUser -> usersField = "ldapUsers";
            case ManagedUser managedUser -> usersField = "managedUsers";
            case OidcUser oidcUser -> usersField = "oidcUsers";
            default -> {
                return null;
            }
        }
        ;

        Query<MappedRole> query = pm.newQuery(MappedRole.class)
                .filter("%s.contains(:user)".formatted(usersField))
                .setNamedParameters(Map.ofEntries(
                        Map.entry("user", user)));

        return executeAndCloseList(query);
    }

    @Override
    public Role getRole(String uuid) {
        final Query<Role> query = pm.newQuery(Role.class, "uuid == :uuid");

        return query.executeUnique();
    }

    public List<Project> getUnassignedProjects(final String username) {
        return getUnassignedProjects(getUserPrincipal(username));
    }

    public List<Permission> getUnassignedRolePermissions(final Role role) {
        // TODO: Implement getUnassignedRolePermissions
        return Collections.emptyList();
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
        return JdbiFactory.withJdbiHandle(handle -> {
            RoleDao dao = handle.attach(RoleDao.class);
            MappedRole mappedRole = dao.addProjectAccessRole(project.getId(), role.getId());

            return dao.addRoleToUser(user, mappedRole.getId()) == 1;
        });
    }

    @Override
    public boolean removeRoleFromUser(UserPrincipal user, Role role, Project project) {
        try (final Handle jdbiHandle = openJdbiHandle()) {
            int count = switch (user) {
                case LdapUser ldapUser -> jdbiHandle.attach(RoleDao.class)
                        .removeRoleFromLdapUser(ldapUser.getId(), project.getId(), role.getId());
                case ManagedUser managedUser -> jdbiHandle.attach(RoleDao.class)
                        .removeRoleFromManagedUser(managedUser.getId(), project.getId(), role.getId());
                case OidcUser oidcUser -> jdbiHandle.attach(RoleDao.class)
                        .removeRoleFromOidcUser(oidcUser.getId(), project.getId(), role.getId());
                default -> 0;
            };

            return count == 1;
        }

    }

}
