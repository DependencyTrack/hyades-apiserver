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

import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.hasColumn;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

/**
 * @since 5.6.0
 */
public class FindingRowMapper implements RowMapper<Finding> {

    private static final TypeReference<List<VulnerabilityAlias>> VULNERABILITY_ALIASES_TYPE_REF = new TypeReference<>() {
    };
    private final RowMapper<Component> componentMapper = BeanMapper.of(Component.class);
    private final RowMapper<Project> projectMapper = BeanMapper.of(Project.class);
    private final RowMapper<Epss> epssMapper = BeanMapper.of(Epss.class);
    private final RowMapper<Vulnerability> vulnerabilityMapper = BeanMapper.of(Vulnerability.class);
    private final RowMapper<Analysis> analysisMapper = BeanMapper.of(Analysis.class);
    private final RowMapper<FindingAttribution> attributionMapper = BeanMapper.of(FindingAttribution.class);

    @Override
    public Finding map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Component component = componentMapper.map(rs, ctx);
        maybeSet(rs, "componentUuid", (ignored, columnName) ->
                UUID.fromString(rs.getString(columnName)), component::setUuid);
        maybeSet(rs, "componentPurl", (ignored, columnName) ->
                rs.getString(columnName), component::setPurl);
        final Project project = projectMapper.map(rs, ctx);
        maybeSet(rs, "projectUuid", (ignored, columnName) ->
                UUID.fromString(rs.getString(columnName)), project::setUuid);
        maybeSet(rs, "projectName", (ignored, columnName) ->
                rs.getString(columnName), project::setName);
        maybeSet(rs, "projectVersion", (ignored, columnName) ->
                rs.getString(columnName), project::setVersion);
        final Epss epss = epssMapper.map(rs, ctx);
        final Analysis analysis = analysisMapper.map(rs, ctx);
        final FindingAttribution attribution = attributionMapper.map(rs, ctx);
        final Vulnerability vulnerability = vulnerabilityMapper.map(rs, ctx);
        maybeSet(rs, "vulnAliasesJson", (ignored, columnName) ->
                deserializeJson(rs, columnName, VULNERABILITY_ALIASES_TYPE_REF), vulnerability::setAliases);
        final Finding finding = new Finding(project, component, vulnerability, epss, analysis, attribution);
        if (hasColumn(rs, "latest_version")) {
            finding.getComponent().put("latestVersion", rs.getString("latest_version"));
        }
        return finding;
    }
}
