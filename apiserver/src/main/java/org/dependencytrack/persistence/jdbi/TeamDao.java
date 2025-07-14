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

import org.dependencytrack.persistence.pagination.Page;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.Collection;
import java.util.List;

import static org.dependencytrack.persistence.pagination.PageUtil.decodePageToken;
import static org.dependencytrack.persistence.pagination.PageUtil.encodePageToken;

public interface TeamDao extends SqlObject {

    record ListTeamsPageToken(String lastName) {
    }

    record ListTeamsRow(String name, int apiKeys, int members) {
    }

    default Page<ListTeamsRow> listTeams(final int limit, final String pageToken) {
        final var decodedPageToken = decodePageToken(getHandle(), pageToken, ListTeamsPageToken.class);

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
                 LIMIT :limit
                """);

        final List<ListTeamsRow> rows = query
                .bind("lastName", decodedPageToken != null
                        ? decodedPageToken.lastName()
                        : null)
                .bind("limit", limit + 1)
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListTeamsRow.class))
                .list();

        final List<ListTeamsRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListTeamsPageToken nextPageToken = rows.size() > limit
                ? new ListTeamsPageToken(resultRows.getLast().name())
                : null;

        return new Page<>(resultRows, encodePageToken(getHandle(), nextPageToken));
    }

    record ListTeamMembershipsPageToken(String lastTeamName, String lastUsername) {
    }

    record ListTeamMembershipsRow(String teamName, String username) {
    }

    default Page<ListTeamMembershipsRow> listTeamMembers(
            final String teamName,
            final String username,
            final int limit,
            final String pageToken) {
        final var decodedPageToken = decodePageToken(getHandle(), pageToken, ListTeamMembershipsPageToken.class);

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="teamName" type="Boolean" -->
                <#-- @ftlvariable name="username" type="Boolean" -->
                <#-- @ftlvariable name="lastTeamName" type="Boolean" -->
                <#-- @ftlvariable name="lastUsername" type="Boolean" -->
                SELECT t."NAME" AS team_name
                     , u."USERNAME" AS username
                  FROM "USERS_TEAMS" AS ut
                 INNER JOIN "TEAM" AS t
                    ON t."ID" = ut."TEAM_ID"
                 INNER JOIN "USER" AS u
                    ON u."ID" = ut."USER_ID"
                 WHERE TRUE
                <#if teamName>
                   AND t."NAME" = :teamName
                </#if>
                <#if username>
                   AND u."USERNAME" = :username
                </#if>
                <#if lastTeamName && lastUsername>
                   AND (t."NAME", u."USERNAME") > (:lastTeamName, :lastUsername)
                </#if>
                 ORDER BY t."NAME", u."USERNAME"
                 LIMIT :limit
                """);

        final List<ListTeamMembershipsRow> rows = query
                .bind("teamName", teamName)
                .bind("username", username)
                .bind("lastTeamName", decodedPageToken != null
                        ? decodedPageToken.lastTeamName()
                        : null)
                .bind("lastUsername", decodedPageToken != null
                        ? decodedPageToken.lastUsername()
                        : null)
                .bind("limit", limit + 1)
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListTeamMembershipsRow.class))
                .list();

        final List<ListTeamMembershipsRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListTeamMembershipsPageToken nextPageToken = rows.size() > limit
                ? new ListTeamMembershipsPageToken(
                resultRows.getLast().teamName(),
                resultRows.getLast().username())
                : null;

        return new Page<>(resultRows, encodePageToken(getHandle(), nextPageToken));
    }

    @SqlUpdate("""
            DELETE
              FROM "USERS_TEAMS"
             WHERE "TEAM_ID" = (SELECT "ID" FROM "TEAM" WHERE "NAME" = :teamName)
               AND "USER_ID" = (SELECT "ID" FROM "USER" WHERE "USERNAME" = :username)
            """)
    boolean deleteTeamMembership(@Bind String teamName, @Bind String username);

    @SqlUpdate("""
            DELETE
              FROM "TEAM"
             WHERE "ID" = :teamId
            """)
    int deleteTeam(@Bind final long teamId);

    default List<String> deleteTeamsByName(final Collection<String> names) {
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
