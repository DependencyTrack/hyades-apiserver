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
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.GetGeneratedKeys;
import org.jdbi.v3.sqlobject.statement.SqlBatch;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
@RegisterRowMapper(CsafProviderRowMapper.class)
public interface CsafProviderDao extends SqlObject {

    @SqlBatch("""
            INSERT INTO "CSAF_PROVIDER" (
              "ID"
            , "NAMESPACE"
            , "NAME"
            , "URL"
            , "DISCOVERED_FROM"
            , "DISCOVERED_AT"
            , "ENABLED"
            , "CREATED_AT"
            )
            VALUES (
              :id
            , :namespace
            , :name
            , :url
            , :discoveredFrom
            , :discoveredAt
            , :enabled
            , :createdAt
            )
            ON CONFLICT ("URL") DO NOTHING
            RETURNING *
            """)
    @GetGeneratedKeys
    List<CsafProvider> createAll(@BindBean Collection<CsafProvider> providers);

    default CsafProvider create(CsafProvider provider) {
        final List<CsafProvider> createdProviders = createAll(List.of(provider));
        if (createdProviders.isEmpty()) {
            throw new AlreadyExistsException("A provider with the same URL already exists.");
        }

        return createdProviders.getFirst();
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="forUpdate" type="boolean" -->
            SELECT *
              FROM "CSAF_PROVIDER"
             WHERE "ID" = :id
            <#if forUpdate>
               FOR UPDATE
            </#if>
            """)
    @Nullable CsafProvider getById(@Bind UUID id, @Define boolean forUpdate);

    default @Nullable CsafProvider getById(UUID id) {
        return getById(id, false);
    }

    default CsafProvider update(CsafProvider provider) {
        final Update update = getHandle().createUpdate("""
                UPDATE "CSAF_PROVIDER"
                   SET "ENABLED" = :enabled
                     , "UPDATED_AT" = NOW()
                 WHERE "ID" = :id
                RETURNING *
                """);

        return update
                .bindBean(provider)
                .executeAndReturnGeneratedKeys()
                .mapTo(CsafProvider.class)
                .findOne()
                .orElseThrow(() -> new NoSuchElementException(
                        "Provider with ID %s does not exist".formatted(provider.getId())));
    }

    @SqlUpdate("""
            UPDATE "CSAF_PROVIDER"
               SET "LATEST_DOCUMENT_RELEASE_DATE" = :latestDocumentReleaseDate
                 , "UPDATED_AT" = NOW()
             WHERE "ID" = :id
               AND (
                 "LATEST_DOCUMENT_RELEASE_DATE" IS NULL
                 OR "LATEST_DOCUMENT_RELEASE_DATE" < :latestDocumentReleaseDate
               )
            """)
    boolean updateLatestDocumentReleaseDateById(@Bind UUID id, @Bind Instant latestDocumentReleaseDate);

    @SqlUpdate("""
            DELETE
              FROM "CSAF_PROVIDER"
             WHERE "ID" = :id
            RETURNING *
            """)
    @GetGeneratedKeys
    @Nullable CsafProvider deleteById(@Bind UUID id);

    record ListProvidersPageToken(long offset) implements PageToken {
    }

    record ListProvidersRow(CsafProvider provider, long totalCount) {

        static class Mapper implements RowMapper<ListProvidersRow> {

            private @Nullable RowMapper<CsafProvider> providerRowMapper;

            @Override
            public void init(ConfigRegistry registry) {
                providerRowMapper = registry.get(RowMappers.class).findFor(CsafProvider.class).orElseThrow();
            }

            @Override
            public ListProvidersRow map(ResultSet rs, StatementContext ctx) throws SQLException {
                requireNonNull(providerRowMapper);
                return new ListProvidersRow(providerRowMapper.map(rs, ctx), rs.getLong("total_count"));
            }

        }

    }

    default Page<CsafProvider> list(ListCsafProvidersQuery listQuery) {
        requireNonNull(listQuery, "listQuery must not be null");

        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(
                listQuery.pageToken(), ListProvidersPageToken.class);

        // Use offset because we don't expect the provider data set
        // to grow large enough to justify keyset pagination.
        final long offset = decodedPageToken != null
                ? decodedPageToken.offset()
                : 0;

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="discoveredFilter" type="boolean" -->
                <#-- @ftlvariable name="enabledFilter" type="boolean" -->
                <#-- @ftlvariable name="offset" type="boolean" -->
                <#-- @ftlvariable name="searchText" type="boolean" -->
                SELECT *
                     , COUNT(*) OVER() AS total_count
                  FROM "CSAF_PROVIDER"
                 WHERE TRUE
                <#if enabledFilter>
                   AND "ENABLED" = :enabledFilter
                </#if>
                <#if discoveredFilter>
                   AND (
                     (:discoveredFilter AND "DISCOVERED_FROM" IS NOT NULL)
                     OR (NOT :discoveredFilter AND "DISCOVERED_FROM" IS NULL)
                   )
                </#if>
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

        final List<ListProvidersRow> rows = query
                .bind("enabledFilter", listQuery.enabled())
                .bind("discoveredFilter", listQuery.discovered())
                .bind("searchText", listQuery.searchText())
                .bind("offset", offset)
                .bind("limit", listQuery.limit())
                .defineNamedBindings()
                .registerRowMapper(new ListProvidersRow.Mapper())
                .mapTo(ListProvidersRow.class)
                .list();

        if (rows.isEmpty()) {
            return Page.empty();
        }

        final List<ListProvidersRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), listQuery.limit()))
                : rows;

        final ListProvidersPageToken nextPageToken = rows.size() > listQuery.limit()
                ? new ListProvidersPageToken(offset + resultRows.size())
                : null;

        return new Page<>(
                resultRows.stream()
                        .map(ListProvidersRow::provider)
                        .toList(),
                pageTokenEncoder.encode(nextPageToken),
                new Page.TotalCount(
                        resultRows.getFirst().totalCount(),
                        Page.TotalCount.Type.EXACT));
    }

}
