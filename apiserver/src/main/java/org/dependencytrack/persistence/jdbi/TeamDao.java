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

import alpine.security.crypto.DataEncryption;
import org.dependencytrack.persistence.pagination.InvalidPageTokenException;
import org.dependencytrack.persistence.pagination.Page;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.Base64;
import java.util.Collection;
import java.util.List;

public interface TeamDao extends SqlObject {

    record ListTeamsPageToken(String lastName) {
    }

    record ListTeamsRow(String name, int members) {
    }

    default Page<ListTeamsRow> listTeams(final int limit, final String pageToken) {
        final var decodedPageToken = decodePageToken(pageToken, ListTeamsPageToken.class);

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastName" type="Boolean" -->
                SELECT "NAME" AS name
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

        return new Page<>(resultRows, encodePageToken(nextPageToken));
    }

    record ListTeamMembersPageToken(String lastUsername) {
    }

    record ListTeamMembersRow(String type, String name, String email) {
    }

    default Page<ListTeamMembersRow> listTeamMembers(final String name, final int limit, final String pageToken) {
        final var decodedPageToken = decodePageToken(pageToken, ListTeamMembersPageToken.class);

        final Query query = getHandle().createQuery(/* language=InjectedFreeMarker */ """
                <#-- @ftlvariable name="lastUsername" type="Boolean" -->
                SELECT u."TYPE" as type
                     , u."USERNAME" AS name
                     , u."EMAIL"
                  FROM "USERS_TEAMS" AS ut
                 INNER JOIN "TEAM" AS t
                    ON t."ID" = ut."TEAM_ID"
                 INNER JOIN "USER" AS u
                    ON u."ID" = ut."USER_ID"
                 WHERE t."NAME" = :teamName
                <#if lastUsername>
                   AND u."USERNAME" > :lastUsername
                </#if>
                 ORDER BY u."USERNAME"
                 LIMIT :limit
                """);

        final List<ListTeamMembersRow> rows = query
                .bind("teamName", name)
                .bind("lastUsername", decodedPageToken != null
                        ? decodedPageToken.lastUsername()
                        : null)
                .bind("limit", limit + 1)
                .defineNamedBindings()
                .map(ConstructorMapper.of(ListTeamMembersRow.class))
                .list();

        final List<ListTeamMembersRow> resultRows = rows.size() > 1
                ? rows.subList(0, Math.min(rows.size(), limit))
                : rows;

        final ListTeamMembersPageToken nextPageToken = rows.size() > limit
                ? new ListTeamMembersPageToken(resultRows.getLast().name())
                : null;

        return new Page<>(resultRows, encodePageToken(nextPageToken));
    }

    @SqlQuery("""
            SELECT EXISTS(
              SELECT 1
                FROM "TEAM"
               WHERE "NAME" = :name
            )
            """)
    boolean doesTeamExist(@Bind String name);

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

    // TODO: Move this to a central place so it's reusable.
    default <T> T decodePageToken(final String encodedToken, final Class<T> tokenClass) {
        if (encodedToken == null) {
            return null;
        }

        final TypedJsonMapper jsonMapper = getHandle()
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(tokenClass, getHandle().getConfig());

        try {
            final byte[] encryptedTokenBytes = Base64.getUrlDecoder().decode(encodedToken);
            final byte[] decryptedToken = DataEncryption.decryptAsBytes(encryptedTokenBytes);
            return (T) jsonMapper.fromJson(new String(decryptedToken), getHandle().getConfig());
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

    // TODO: Move this to a central place so it's reusable.
    default <T> String encodePageToken(final T pageToken) {
        if (pageToken == null) {
            return null;
        }

        final TypedJsonMapper jsonMapper = getHandle()
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(Object.class, getHandle().getConfig());

        try {
            final String tokenJson = jsonMapper.toJson(pageToken, getHandle().getConfig());
            final byte[] encryptedTokenBytes = DataEncryption.encryptAsBytes(tokenJson);
            return Base64.getUrlEncoder().encodeToString(encryptedTokenBytes);
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
