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
package org.dependencytrack.persistence.jdbi;

import jakarta.annotation.Nullable;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.persistence.jdbi.query.ListAdvisoriesForProjectQuery;
import org.dependencytrack.persistence.jdbi.query.ListAdvisoriesQuery;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * JDBI Data Access Object for performing operations on {@link Advisory}
 * objects.
 */
public interface AdvisoryDao extends PaginationSupport {

    record ListProjectAdvisoriesRow(
            UUID id,
            String publisher,
            String name,
            String version,
            URI url,
            String title,
            String format,
            Instant seenAt,
            Instant lastFetched,
            long findingsCount,
            long totalCount) {
    }

    record ListAdvisoriesForProjectPageToken(long offset) implements PageToken {
    }

    default Page<ListProjectAdvisoriesRow> listForProject(ListAdvisoriesForProjectQuery listQuery) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(
                listQuery.pageToken(), ListAdvisoriesForProjectPageToken.class);

        final long offset = decodedPageToken != null
                ? decodedPageToken.offset()
                : 0;

        final Query query = getHandle().createQuery("""
                SELECT a."ID"
                     , a."PUBLISHER"
                     , a."NAME"
                     , a."VERSION"
                     , a."URL"
                     , a."TITLE"
                     , a."FORMAT"
                     , a."SEEN_AT"
                     , a."LASTFETCHED"
                     , COUNT(cv."VULNERABILITY_ID") AS findings_count
                     , COUNT(*) OVER() AS total_count
                  FROM "COMPONENT" AS c
                 INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                    ON cv."COMPONENT_ID" = c."ID"
                 INNER JOIN "ADVISORIES_VULNERABILITIES" AS av
                    ON av."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                 INNER JOIN "ADVISORY" AS a
                    ON av."ADVISORY_ID" = a."ID"
                 WHERE c."PROJECT_ID" = :projectId
                   AND ${apiProjectAclCondition!"TRUE"}
                   AND EXISTS(
                         SELECT 1
                           FROM "FINDINGATTRIBUTION" AS fa
                          WHERE fa."COMPONENT_ID" = c."ID"
                            AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                            AND fa."DELETED_AT" IS NULL
                       )
                 GROUP BY a."ID"
                 ORDER BY a."ID"
                OFFSET :offset
                 LIMIT (:limit + 1)
                """);

        final List<ListProjectAdvisoriesRow> rows = query
                .addCustomizer(
                        new DefineApiProjectAclCondition.StatementCustomizer(
                                JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                                "c.\"PROJECT_ID\""))
                .bind("projectId", listQuery.projectId())
                .bind("offset", offset)
                .bind("limit", listQuery.limit())
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListProjectAdvisoriesRow.class))
                .list();

        if (rows.isEmpty()) {
            return Page.empty();
        }

        final List<ListProjectAdvisoriesRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), listQuery.limit()))
                : rows;

        final ListAdvisoriesForProjectPageToken nextPageToken = rows.size() > listQuery.limit()
                ? new ListAdvisoriesForProjectPageToken(offset + resultRows.size())
                : null;

        return new Page<>(
                resultRows,
                pageTokenEncoder.encode(nextPageToken),
                new Page.TotalCount(
                        resultRows.getFirst().totalCount(),
                        Page.TotalCount.Type.EXACT));
    }

    record AdvisoryDetailRow(
            UUID id,
            String title,
            URI url,
            Instant seenAt,
            Instant lastFetched,
            String publisher,
            String name,
            String version,
            String format,
            int affectedComponentCount,
            int affectedProjectCount,
            @Nullable String content) {
    }

    record ListAdvisoriesPageToken(long offset) implements PageToken {
    }

    record ListAdvisoriesRow(
            UUID id,
            String publisher,
            String name,
            String version,
            URI url,
            String title,
            String format,
            Instant lastFetched,
            Instant seenAt,
            int affectedComponentCount,
            int affectedProjectCount,
            long totalCount) {
    }

    default Page<ListAdvisoriesRow> list(ListAdvisoriesQuery listQuery) {
        requireNonNull(listQuery, "listQuery must not be null");

        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(
                listQuery.pageToken(), ListAdvisoriesPageToken.class);

        final long offset = decodedPageToken != null
                ? decodedPageToken.offset()
                : 0;

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="apiProjectAclCondition" type="String" -->
                <#-- @ftlvariable name="formatFilter" type="boolean" -->
                <#-- @ftlvariable name="searchText" type="boolean" -->
                SELECT "ID"
                     , "TITLE"
                     , "URL"
                     , "SEEN_AT"
                     , "LASTFETCHED"
                     , "PUBLISHER"
                     , "NAME"
                     , "VERSION"
                     , "FORMAT"
                     , (
                         SELECT COUNT(*)
                           FROM (
                             SELECT DISTINCT c."ID"
                               FROM "ADVISORIES_VULNERABILITIES" AS av
                              INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                                 ON cv."VULNERABILITY_ID" = av."VULNERABILITY_ID"
                              INNER JOIN "COMPONENT" AS c
                                 ON c."ID" = cv."COMPONENT_ID"
                              WHERE av."ADVISORY_ID" = a."ID"
                                AND ${apiProjectAclCondition!"TRUE"}
                                AND EXISTS(
                                      SELECT 1
                                        FROM "FINDINGATTRIBUTION" AS fa
                                       WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
                                         AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                                         AND fa."DELETED_AT" IS NULL
                                    )
                              LIMIT 1001
                           ) AS t
                       ) AS affected_component_count
                     , (
                         SELECT COUNT(*)
                           FROM (
                             SELECT DISTINCT c."PROJECT_ID"
                               FROM "ADVISORIES_VULNERABILITIES" AS av
                              INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                                 ON cv."VULNERABILITY_ID" = av."VULNERABILITY_ID"
                              INNER JOIN "COMPONENT" AS c
                                 ON c."ID" = cv."COMPONENT_ID"
                              WHERE av."ADVISORY_ID" = a."ID"
                                AND ${apiProjectAclCondition!"TRUE"}
                                AND EXISTS(
                                      SELECT 1
                                        FROM "FINDINGATTRIBUTION" AS fa
                                       WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
                                         AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                                         AND fa."DELETED_AT" IS NULL
                                    )
                              LIMIT 1001
                           ) AS t
                       ) AS affected_project_count
                     , COUNT(*) OVER() AS total_count
                  FROM "ADVISORY" AS a
                 WHERE TRUE
                <#if formatFilter>
                   AND "FORMAT" = :formatFilter
                </#if>
                <#if searchText>
                   AND "SEARCHVECTOR" @@ websearch_to_tsquery(:searchText)
                </#if>
                 ORDER BY "NAME"
                OFFSET :offset
                 LIMIT (:limit + 1)
                """);

        final List<ListAdvisoriesRow> rows = query
                .addCustomizer(
                        new DefineApiProjectAclCondition.StatementCustomizer(
                                JdbiAttributes.ATTRIBUTE_API_PROJECT_ACL_CONDITION,
                                "c.\"PROJECT_ID\""))
                .bind("formatFilter", listQuery.format())
                .bind("searchText", listQuery.searchText())
                .bind("offset", offset)
                .bind("limit", listQuery.limit())
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListAdvisoriesRow.class))
                .list();

        if (rows.isEmpty()) {
            return Page.empty();
        }

        final List<ListAdvisoriesRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), listQuery.limit()))
                : rows;

        final ListAdvisoriesPageToken nextPageToken = rows.size() > listQuery.limit()
                ? new ListAdvisoriesPageToken(offset + resultRows.size())
                : null;

        return new Page<>(
                resultRows,
                pageTokenEncoder.encode(nextPageToken),
                new Page.TotalCount(
                        resultRows.getFirst().totalCount(),
                        Page.TotalCount.Type.EXACT));
    }

    @SqlQuery("""
            SELECT "ID"
                 , "TITLE"
                 , "URL"
                 , "SEEN_AT"
                 , "LASTFETCHED"
                 , "PUBLISHER"
                 , "NAME"
                 , "VERSION"
                 , "FORMAT"
                 , "CONTENT"
                 , (
                     SELECT COUNT(*)
                       FROM (
                         SELECT DISTINCT c."ID"
                           FROM "ADVISORIES_VULNERABILITIES" AS av
                          INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                             ON cv."VULNERABILITY_ID" = av."VULNERABILITY_ID"
                          INNER JOIN "COMPONENT" AS c
                             ON c."ID" = cv."COMPONENT_ID"
                          WHERE av."ADVISORY_ID" = a."ID"
                            AND ${apiProjectAclCondition}
                            AND EXISTS(
                                  SELECT 1
                                    FROM "FINDINGATTRIBUTION" AS fa
                                   WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
                                     AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                                     AND fa."DELETED_AT" IS NULL
                                )
                          LIMIT 1001
                       ) AS t
                    ) AS affected_component_count
                 , (
                     SELECT COUNT(*)
                       FROM (
                         SELECT DISTINCT c."PROJECT_ID"
                           FROM "ADVISORIES_VULNERABILITIES" AS av
                          INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                             ON cv."VULNERABILITY_ID" = av."VULNERABILITY_ID"
                          INNER JOIN "COMPONENT" AS c
                             ON c."ID" = cv."COMPONENT_ID"
                          WHERE av."ADVISORY_ID" = a."ID"
                            AND ${apiProjectAclCondition}
                            AND EXISTS(
                                  SELECT 1
                                    FROM "FINDINGATTRIBUTION" AS fa
                                   WHERE fa."COMPONENT_ID" = cv."COMPONENT_ID"
                                     AND fa."VULNERABILITY_ID" = cv."VULNERABILITY_ID"
                                     AND fa."DELETED_AT" IS NULL
                                )
                          LIMIT 1001
                       ) AS t
                    ) AS affected_project_count
              FROM "ADVISORY" AS a
             WHERE "ID" = :id
            """)
    @DefineApiProjectAclCondition(projectIdColumn = "c.\"PROJECT_ID\"")
    @RegisterConstructorMapper(AdvisoryDetailRow.class)
    AdvisoryDetailRow getById(@Bind UUID id);

    @SqlUpdate(/* language=SQL */ """
            UPDATE "ADVISORY"
               SET "SEEN_AT" = NOW()
             WHERE "ID" = :id
            """)
    boolean markAsSeen(@Bind UUID id);

    record ProjectAdvisoryFindingRow(
            String name,
            short confidence,
            String desc,
            String group,
            String version,
            String componentUuid) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "COMPONENT"."NAME" AS "name"
               , "MATCHING_PERCENTAGE" AS "confidence"
               , "DESCRIPTION" AS "desc"
               , "GROUP" AS "group"
               , "COMPONENT"."VERSION" AS "version"
               , "COMPONENT"."UUID" AS "componentUuid"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "COMPONENT" ON "FINDINGATTRIBUTION"."COMPONENT_ID" = "COMPONENT"."ID"
            INNER JOIN "ADVISORIES_VULNERABILITIES"
              ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            INNER JOIN "ADVISORY" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            WHERE "FINDINGATTRIBUTION"."PROJECT_ID" = :projectId
            AND "ADVISORY_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(ProjectAdvisoryFindingRow.class)
    List<ProjectAdvisoryFindingRow> getFindingsByProjectAdvisory(
            @Bind long projectId,
            @Bind UUID advisoryId);

    @SqlUpdate("""
            DELETE
              FROM "ADVISORY"
             WHERE "ID" = :id
            """)
    boolean deleteById(@Bind UUID id);

}
