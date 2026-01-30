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

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.PageToken;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

@NullMarked
public interface TeamDao extends PaginationSupport {

    record ListTeamsPageToken(String lastName, TotalCount totalCount) implements PageToken {
    }

    record ListTeamsRow(String name, int apiKeys, int members) {
    }

    default Page<ListTeamsRow> listTeams(int limit, @Nullable String pageToken) {
        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListTeamsPageToken.class);

        TotalCount totalCount;
        String lastName = null;

        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
            lastName = decodedPageToken.lastName();
        } else {
            totalCount = getBoundedTotalCount("FROM \"TEAM\"", null, 500);
        }

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="Boolean" -->
                SELECT "NAME" AS name
                     , (SELECT COUNT(*) FROM "APIKEYS_TEAMS" WHERE "TEAM_ID" = "TEAM"."ID") AS api_keys
                     , (SELECT COUNT(*) FROM "USERS_TEAMS" WHERE "TEAM_ID" = "TEAM"."ID") AS members
                  FROM "TEAM"
                 WHERE TRUE
                <#if lastName>
                   AND "NAME" > :lastName
                </#if>
                 ORDER BY "NAME"
                 LIMIT (:limit + 1)
                """);

        final List<ListTeamsRow> rows = query
                .bind("lastName", lastName)
                .bind("limit", limit)
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListTeamsRow.class))
                .list();

        final List<ListTeamsRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListTeamsPageToken nextPageToken = rows.size() > limit
                ? new ListTeamsPageToken(resultRows.getLast().name(), totalCount)
                : null;

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    record ListTeamMembershipsPageToken(
            String lastTeamName,
            String lastUsername,
            TotalCount totalCount) implements PageToken {
    }

    record ListTeamMembershipsRow(String teamName, String username) {
    }

    default Page<ListTeamMembershipsRow> listTeamMembers(
            @Nullable String teamName,
            @Nullable String username,
            int limit,
            @Nullable String pageToken) {
        final var whereConditions = new ArrayList<String>();
        final var queryParams = new HashMap<String, Object>();

        whereConditions.add("TRUE");
        if (teamName != null) {
            whereConditions.add("t.\"NAME\" = :teamName");
            queryParams.put("teamName", teamName);
        }
        if (username != null) {
            whereConditions.add("u.\"USERNAME\" = :username");
            queryParams.put("username", username);
        }

        final PageTokenEncoder pageTokenEncoder =
                getHandle().getConfig(PaginationConfig.class).getPageTokenEncoder();
        final var decodedPageToken = pageTokenEncoder.decode(pageToken, ListTeamMembershipsPageToken.class);

        TotalCount totalCount;
        String lastTeamName = null;
        String lastUsername = null;

        if (decodedPageToken != null) {
            totalCount = decodedPageToken.totalCount();
            lastTeamName = decodedPageToken.lastTeamName();
            lastUsername = decodedPageToken.lastUsername();
        } else {
            totalCount = getBoundedTotalCount("""
                             FROM "USERS_TEAMS" AS ut
                            INNER JOIN "TEAM" AS t
                               ON t."ID" = ut."TEAM_ID"
                            INNER JOIN "USER" AS u
                               ON u."ID" = ut."USER_ID"
                            WHERE %s
                            """.formatted(String.join(" AND ", whereConditions)),
                    queryParams,
                    500);
        }

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="teamName" type="Boolean" -->
                <#-- @ftlvariable name="username" type="Boolean" -->
                <#-- @ftlvariable name="lastTeamName" type="Boolean" -->
                <#-- @ftlvariable name="lastUsername" type="Boolean" -->
                <#-- @ftlvariable name="whereConditions" type="java.util.Collection<String>" -->
                SELECT t."NAME" AS team_name
                     , u."USERNAME" AS username
                  FROM "USERS_TEAMS" AS ut
                 INNER JOIN "TEAM" AS t
                    ON t."ID" = ut."TEAM_ID"
                 INNER JOIN "USER" AS u
                    ON u."ID" = ut."USER_ID"
                 WHERE ${whereConditions?join(" AND ")}
                <#if lastTeamName && lastUsername>
                   AND (t."NAME", u."USERNAME") > (:lastTeamName, :lastUsername)
                </#if>
                 ORDER BY t."NAME", u."USERNAME"
                 LIMIT (:limit + 1)
                """);

        final List<ListTeamMembershipsRow> rows = query
                .bindMap(queryParams)
                .bind("lastTeamName", lastTeamName)
                .bind("lastUsername", lastUsername)
                .bind("limit", limit)
                .define("whereConditions", whereConditions)
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListTeamMembershipsRow.class))
                .list();

        final List<ListTeamMembershipsRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListTeamMembershipsPageToken nextPageToken = rows.size() > limit
                ? new ListTeamMembershipsPageToken(
                resultRows.getLast().teamName(),
                resultRows.getLast().username(),
                totalCount)
                : null;

        return new Page<>(resultRows, pageTokenEncoder.encode(nextPageToken), totalCount);
    }

    @SqlUpdate("""
            DELETE
              FROM "USERS_TEAMS"
             WHERE "TEAM_ID" = (SELECT "ID" FROM "TEAM" WHERE "NAME" = :teamName)
               AND "USER_ID" = (SELECT "ID" FROM "USER" WHERE "USERNAME" = :username)
            """)
    boolean deleteTeamMembership(@Bind String teamName, @Bind String username);

    default List<String> deleteTeamsByName(Collection<String> names) {
        final Update update = getHandle().createUpdate("""
                DELETE
                  FROM "TEAM"
                 WHERE "NAME" = ANY(:names)
                RETURNING "NAME"
                """);

        return update
                .bindArray("names", String.class, names)
                .executeAndReturnGeneratedKeys()
                .mapTo(String.class)
                .list();
    }

}
