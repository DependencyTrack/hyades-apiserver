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

import org.dependencytrack.proto.notification.v1.Bom;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.jdbi.v3.core.mapper.NoSuchMapperException;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationSubjectBomConsumedOrProcessedRowMapper implements RowMapper<BomConsumedOrProcessedSubject> {

    @Override
    public BomConsumedOrProcessedSubject map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final RowMapper<Project> projectRowMapper = ctx.findRowMapperFor(Project.class)
                .orElseThrow(() -> new NoSuchMapperException("No mapper registered for %s".formatted(Project.class)));
        final RowMapper<Bom> bomRowMapper = ctx.findRowMapperFor(Bom.class)
                .orElseThrow(() -> new NoSuchMapperException("No mapper registered for %s".formatted(Bom.class)));

        final BomConsumedOrProcessedSubject.Builder builder = BomConsumedOrProcessedSubject.newBuilder()
                .setProject(projectRowMapper.map(rs, ctx))
                .setBom(bomRowMapper.map(rs, ctx));
        maybeSet(rs, "token", ResultSet::getString, builder::setToken);

        return builder.build();
    }

}
