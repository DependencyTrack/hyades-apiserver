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
package org.dependencytrack.csaf;

import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public class CsafProviderRowMapper implements RowMapper<CsafProvider> {

    private @Nullable ColumnMapper<Instant> instantColumnMapper;

    @Override
    public void init(ConfigRegistry registry) {
        instantColumnMapper = registry.get(ColumnMappers.class).findFor(Instant.class).orElseThrow();
    }

    @Override
    public CsafProvider map(ResultSet rs, StatementContext ctx) throws SQLException {
        requireNonNull(instantColumnMapper);

        final var provider = new CsafProvider(
                rs.getObject("id", UUID.class),
                URI.create(rs.getString("url")),
                URI.create(rs.getString("namespace")),
                rs.getString("name"));
        provider.setEnabled(rs.getBoolean("enabled"));
        provider.setDiscoveredFrom(rs.getObject("discovered_from", UUID.class));
        provider.setDiscoveredAt(instantColumnMapper.map(rs, "discovered_at", ctx));
        provider.setLatestDocumentReleaseDate(instantColumnMapper.map(rs, "latest_document_release_date", ctx));
        provider.setCreatedAt(instantColumnMapper.map(rs, "created_at", ctx));
        provider.setUpdatedAt(instantColumnMapper.map(rs, "updated_at", ctx));
        return provider;
    }

}
