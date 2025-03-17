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

import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.model.ProjectRole.LdapUserProjectRole;
import org.dependencytrack.model.ProjectRole.ManagedUserProjectRole;
import org.dependencytrack.model.ProjectRole.OidcUserProjectRole;
import org.dependencytrack.model.Role;

import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.hasColumn;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class ProjectRoleRowMapper implements RowMapper<ProjectRole> {

    public ProjectRole map(final ResultSet resultSet, final StatementContext ctx) throws SQLException {
        ProjectRole projectRole;

        switch (resultSet) {
            case ResultSet rs when hasColumn(rs, "LDAPUSER_ID") -> projectRole = new LdapUserProjectRole();
            case ResultSet rs when hasColumn(rs, "MANAGEDUSER_ID") -> projectRole = new ManagedUserProjectRole();
            case ResultSet rs when hasColumn(rs, "OIDCUSER_ID") -> projectRole = new OidcUserProjectRole();
            default -> {
                return null;
            }
        }

        maybeSet(resultSet, "PROJECT_ID", ResultSet::getLong, value -> {
            var project = new Project();
            project.setId(value);
            projectRole.setProject(project);
        });

        maybeSet(resultSet, "ROLE_ID", ResultSet::getLong, value -> {
            var role = new Role();
            role.setId(value);
            projectRole.setRole(role);
        });

        return projectRole;
    }

}
