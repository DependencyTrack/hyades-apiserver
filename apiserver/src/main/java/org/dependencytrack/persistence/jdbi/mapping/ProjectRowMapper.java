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

import alpine.model.Team;
import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

/**
 * @since 5.6.0
 */
public class ProjectRowMapper implements RowMapper<ProjectDao.ProjectRow> {

    private static final TypeReference<Set<Tag>> TAGS_TYPE_REF = new TypeReference<>() {};
    private static final TypeReference<Set<Team>> TEAMS_TYPE_REF = new TypeReference<>() {};

    private final RowMapper<Project> projectMapper = BeanMapper.of(Project.class);

    @Override
    public ProjectDao.ProjectRow map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Project project = projectMapper.map(rs, ctx);
        maybeSet(rs, "projectPurl", ResultSet::getString, project::setPurl);
        maybeSet(rs, "teamsJson", (ignored, columnName) ->
                deserializeJson(rs, columnName, TEAMS_TYPE_REF), project::setAccessTeams);
        maybeSet(rs, "tagsJson", (ignored, columnName) ->
                deserializeJson(rs, columnName, TAGS_TYPE_REF), project::setTags);
        final ProjectDao.ProjectRow projectRow = new ProjectDao.ProjectRow(project, rs.getInt("totalCount"));
        return projectRow;
    }
}
