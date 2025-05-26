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
package org.dependencytrack.persistence.jdbi.mapping;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.User;

import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectRoleBinding;
import org.dependencytrack.model.Role;

import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class ProjectRoleRowBindingMapper implements RowMapper<ProjectRoleBinding> {

    public ProjectRoleBinding map(final ResultSet resultSet, final StatementContext ctx) throws SQLException {
        final ProjectRoleBinding projectRole = new ProjectRoleBinding();
        projectRole.setProject(new Project());
        projectRole.setRole(new Role());

        final String type = resultSet.getString("USER_TYPE");
        final User user = switch (type) {
            case "LDAP" -> new LdapUser();
            case "MANAGED" -> new ManagedUser();
            case "OIDC" -> new OidcUser();
            default -> null;
        };

        if (user == null)
            return projectRole;

        maybeSet(resultSet, "USER_ID", ResultSet::getLong, user::setId);
        maybeSet(resultSet, "USER_NAME", ResultSet::getString, user::setUsername);
        projectRole.addUsers(user);

        maybeSet(resultSet, "PROJECT_ID", ResultSet::getLong, projectRole.getProject()::setId);
        maybeSet(resultSet, "PROJECT_NAME", ResultSet::getString, projectRole.getProject()::setName);
        maybeSet(resultSet, "PROJECT_UUID", ResultSet::getString, value -> {
            projectRole.getProject().setUuid(UUID.fromString(value));
        });

        maybeSet(resultSet, "ROLE_ID", ResultSet::getLong, projectRole.getRole()::setId);
        maybeSet(resultSet, "ROLE_NAME", ResultSet::getString, projectRole.getRole()::setName);
        maybeSet(resultSet, "ROLE_UUID", ResultSet::getString, value -> {
            projectRole.getRole().setUuid(UUID.fromString(value));
        });

        return projectRole;
    }

}
