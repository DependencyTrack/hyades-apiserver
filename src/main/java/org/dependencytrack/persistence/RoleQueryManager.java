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

import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.List;

import javax.jdo.PersistenceManager;

import org.dependencytrack.model.Role;

import alpine.common.logging.Logger;
import alpine.model.Permission;
import alpine.resources.AlpineRequest;

final class RoleQueryManager extends QueryManager implements IQueryManager {

    private static final Logger LOGGER = Logger.getLogger(ProjectQueryManager.class);

    RoleQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    RoleQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public Role createRole(final String name, final String description, final List<Permission> permissions) {
        Role role = new Role();
        role.setName(name);
        role.setDescription(description);
        role.setPermissions(permissions);

        return persist(role);
    }

    public List<Role> getRoles() {
        // TODO:Implement role retrieval logic
        return Collections.emptyList();
    }

    public Role getRole(String uuid) {
        // TODO:Implement role retrieval logic
        return null;
    }

    public Role updateRole(Role role) {
        // TODO:Implement role update logic
        return role;
    }

    public boolean deleteRole(String uuid, boolean value) {
        // TODO:Implement role deletion logic
        return false;
    }

    boolean addRoleToUser(UserPrincipal principal, Role role, String roleName, String projectName) {
        // WARNING: This method is a stub.
        // TODO: Implement addRoleToUser
        return true;
    }

    boolean removeRoleFromUser(UserPrincipal principal, Role role, String roleName, String projectName) {
        // WARNING: This method is a stub.
        // TODO: Implement removeRoleFromUser
        return true;
    }
}
