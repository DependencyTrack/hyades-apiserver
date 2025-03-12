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

import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.model.Vulnerability;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.reflect.BeanMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

/**
 * @since 5.6.0
 */
public class GroupedFindingRowMapper implements RowMapper<GroupedFinding> {

    private final RowMapper<Vulnerability> vulnerabilityMapper = BeanMapper.of(Vulnerability.class);
    private final RowMapper<FindingAttribution> attributionMapper = BeanMapper.of(FindingAttribution.class);

    @Override
    public GroupedFinding map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Vulnerability vulnerability = vulnerabilityMapper.map(rs, ctx);
        final FindingAttribution attribution = attributionMapper.map(rs, ctx);
        maybeSet(rs, "affectedProjectCount", (ignored, columnName) ->
                rs.getInt(columnName), vulnerability::setAffectedProjectCount);
        return new GroupedFinding(vulnerability, attribution);
    }
}
