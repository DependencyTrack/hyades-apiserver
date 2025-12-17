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

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.persistence.jdbi.PaginationConfig;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.mapper.RowMappers;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.StatementContext;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
@RegisterRowMapper(CsafAggregatorRowMapper.class)
public interface CsafAggregatorDao extends SqlObject {

    default CsafAggregator create(CsafAggregator aggregator) {
        final Update update = getHandle().createUpdate("""
                INSERT INTO "CSAF_AGGREGATOR" ("ID", "NAMESPACE", "NAME", "URL", "ENABLED", "CREATED_AT")
                VALUES (:id, :namespace, :name, :url, :enabled, :createdAt)
                ON CONFLICT ("URL") DO NOTHING
                RETURNING *
                """);

        final CsafAggregator createdAggregator = update
                .bindBean(aggregator)
                .executeAndReturnGeneratedKeys()
                .mapTo(CsafAggregator.class)
                .findOne()
                .orElse(null);

        if (createdAggregator == null) {
            throw new AlreadyExistsException("An aggregator with the same URL already exists.");
        }

        return createdAggregator;
    }

    default CsafAggregator update(CsafAggregator aggregator) {
        final Update update = getHandle().createUpdate("""
                UPDATE "CSAF_AGGREGATOR"
                   SET "ENABLED" = :enabled
                     , "UPDATED_AT" = NOW()
                 WHERE "ID" = :id
                RETURNING *
                """);

        return update
                .bindBean(aggregator)
                .executeAndReturnGeneratedKeys()
                .mapTo(CsafAggregator.class)
                .findOne()
                .orElseThrow(() -> new NoSuchElementException(
                        "Aggregator with ID %s does not exist".formatted(aggregator.getId())));
    }

    @SqlUpdate("""
            UPDATE "CSAF_AGGREGATOR"
               SET "LAST_DISCOVERY_AT" = :lastDiscoveryAt
                 , "UPDATED_AT" = NOW()
             WHERE "ID" = :id
               AND ("LAST_DISCOVERY_AT" IS NULL OR "LAST_DISCOVERY_AT" < :lastDiscoveryAt)
            """)
    boolean updateLastDiscoveryAtById(@Bind UUID id, @Bind Instant lastDiscoveryAt);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="forUpdate" type="boolean" -->
            SELECT *
              FROM "CSAF_AGGREGATOR"
             WHERE "ID" = :id
            <#if forUpdate>
               FOR UPDATE
            </#if>
            """)
    @Nullable CsafAggregator getById(@Bind UUID id, @Define boolean forUpdate);

    default @Nullable CsafAggregator getById(UUID id) {
        return getById(id, false);
    }

    @SqlUpdate("""
            DELETE
              FROM "CSAF_AGGREGATOR"
             WHERE "ID" = :id
            RETURNING *
            """)
    @GetGeneratedKeys
    @Nullable CsafAggregator deleteById(@Bind UUID id);

    record ListAggregatorsPageToken(long offset) implements PageToken {
    }

    record ListAggregatorsRow(CsafAggregator aggregator, long totalCount) {

        static class Mapper implements RowMapper<ListAggregatorsRow> {

            private @Nullable RowMapper<CsafAggregator> aggregatorRowMapper;

            @Override
            public void init(ConfigRegistry registry) {
                aggregatorRowMapper = registry.get(RowMappers.class).findFor(CsafAggregator.class).orElseThrow();
            }

            @Override
            public ListAggregatorsRow map(ResultSet rs, StatementContext ctx) throws SQLException {
                requireNonNull(aggregatorRowMapper);
                return new ListAggregatorsRow(aggregatorRowMapper.map(rs, ctx), rs.getLong("total_count"));
            }

        }

    }

    default Page<CsafAggregator> list(ListCsafAggregatorsQuery listQuery) {
        requireNonNull(listQuery, "listQuery must not be null");

        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(
                listQuery.pageToken(), ListAggregatorsPageToken.class);

        // Use offset because we don't expect the aggregator data set
        // to grow large enough to justify keyset pagination.
        final long offset = decodedPageToken != null
                ? decodedPageToken.offset()
                : 0;

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="searchText" type="boolean" -->
                SELECT *
                     , COUNT(*) OVER() AS total_count
                  FROM "CSAF_AGGREGATOR"
                 WHERE TRUE
                <#if searchText>
                   AND (
                     (LOWER("NAMESPACE") LIKE ('%' || LOWER(:searchText) || '%'))
                     OR (LOWER("NAME") LIKE ('%' || LOWER(:searchText) || '%'))
                     OR (LOWER("URL") LIKE ('%' || LOWER(:searchText) || '%'))
                   )
                </#if>
                 ORDER BY "NAMESPACE"
                OFFSET :offset
                 LIMIT (:limit + 1)
                """);

        final List<ListAggregatorsRow> rows = query
                .bind("searchText", listQuery.searchText())
                .bind("offset", offset)
                .bind("limit", listQuery.limit())
                .defineNamedBindings()
                .registerRowMapper(new ListAggregatorsRow.Mapper())
                .mapTo(ListAggregatorsRow.class)
                .list();

        if (rows.isEmpty()) {
            return Page.empty();
        }

        final List<ListAggregatorsRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), listQuery.limit()))
                : rows;

        final ListAggregatorsPageToken nextPageToken = rows.size() > listQuery.limit()
                ? new ListAggregatorsPageToken(offset + resultRows.size())
                : null;

        return new Page<>(
                resultRows.stream()
                        .map(ListAggregatorsRow::aggregator)
                        .toList(),
                pageTokenEncoder.encode(nextPageToken),
                new Page.TotalCount(
                        resultRows.getFirst().totalCount(),
                        Page.TotalCount.Type.EXACT));
    }

}
