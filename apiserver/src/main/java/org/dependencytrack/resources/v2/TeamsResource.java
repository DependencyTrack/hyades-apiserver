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
package org.dependencytrack.resources.v2;

import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import alpine.server.auth.PermissionRequired;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.TeamsApi;
import org.dependencytrack.api.v2.model.BulkCreateTeamMembershipsRequest;
import org.dependencytrack.api.v2.model.BulkCreateTeamMembershipsRequestItem;
import org.dependencytrack.api.v2.model.BulkCreateTeamMembershipsResponse;
import org.dependencytrack.api.v2.model.BulkCreateTeamMembershipsResponseItem;
import org.dependencytrack.api.v2.model.BulkCreateTeamsRequest;
import org.dependencytrack.api.v2.model.BulkCreateTeamsRequestItem;
import org.dependencytrack.api.v2.model.BulkCreateTeamsResponse;
import org.dependencytrack.api.v2.model.BulkCreateTeamsResponseItem;
import org.dependencytrack.api.v2.model.BulkDeleteTeamResult;
import org.dependencytrack.api.v2.model.BulkDeleteTeamsResponse;
import org.dependencytrack.api.v2.model.GetTeamResponse;
import org.dependencytrack.api.v2.model.ListTeamMembershipsResponse;
import org.dependencytrack.api.v2.model.ListTeamMembershipsResponseItem;
import org.dependencytrack.api.v2.model.ListTeamsResponse;
import org.dependencytrack.api.v2.model.ListTeamsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.TeamDao;
import org.dependencytrack.persistence.jdbi.TeamDao.ListTeamMembershipsRow;
import org.dependencytrack.persistence.jdbi.TeamDao.ListTeamsRow;
import org.dependencytrack.persistence.pagination.Page;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.util.PageUtil.createPaginationMetadata;

@Provider
public class TeamsResource implements TeamsApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(TeamsResource.class);

    @Context
    private UriInfo uriInfo;

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response listTeams(final Integer limit, final String pageToken) {
        final Page<ListTeamsRow> teamsPage = inJdbiTransaction(
                handle -> handle.attach(TeamDao.class).listTeams(limit, pageToken));

        final var response = ListTeamsResponse.builder()
                .teams(teamsPage.items().stream()
                        .<ListTeamsResponseItem>map(
                                teamRow -> ListTeamsResponseItem.builder()
                                        .name(teamRow.name())
                                        .apiKeys(teamRow.apiKeys())
                                        .members(teamRow.members())
                                        .build())
                        .toList())
                .pagination(createPaginationMetadata(uriInfo, teamsPage))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getTeam(final String name) {
        try (final var qm = new QueryManager()) {
            final Team team = qm.getTeam(name);
            if (team == null) {
                throw new NotFoundException();
            }

            final var response = GetTeamResponse.builder()
                    .name(name)
                    .permissions(
                            team.getPermissions().stream()
                                    .map(Permission::getName)
                                    .sorted()
                                    .toList())
                    .build();

            return Response.ok(response).build();
        }
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response createTeams(final BulkCreateTeamsRequest bulkRequest) {
        final long uniqueBulksRequestItemIds = bulkRequest.getTeams().stream()
                .map(BulkCreateTeamsRequestItem::getId)
                .distinct()
                .count();
        if (uniqueBulksRequestItemIds < bulkRequest.getTeams().size()) {
            throw new BadRequestException("Bulk request item IDs are not unique.");
        }

        final Set<String> allPermissionNames =
                bulkRequest.getTeams().stream()
                        .flatMap(team -> team.getPermissions().stream())
                        .collect(Collectors.toSet());

        final var statusByBulkItemId = new HashMap<String, String>(bulkRequest.getTeams().size());

        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final Map<String, Permission> permissionByName =
                        qm.getPermissionsByName(allPermissionNames).stream()
                                .collect(Collectors.toMap(Permission::getName, Function.identity()));

                for (final BulkCreateTeamsRequestItem bulkItem : bulkRequest.getTeams()) {
                    final List<Permission> permissions = bulkItem.getPermissions().stream()
                            .map(permissionByName::get)
                            .filter(Objects::nonNull)
                            .toList();

                    Team team = qm.getTeam(bulkItem.getName());
                    if (team != null) {
                        statusByBulkItemId.put(bulkItem.getId(), "ALREADY_EXISTS");
                        continue;
                    }

                    team = qm.createTeam(bulkItem.getName());
                    team.setPermissions(permissions);
                    statusByBulkItemId.put(bulkItem.getId(), "CREATED");
                }
            });
        }

        final var response = BulkCreateTeamsResponse.builder()
                .teams(statusByBulkItemId.entrySet().stream()
                        .<BulkCreateTeamsResponseItem>map(
                                entry -> BulkCreateTeamsResponseItem.builder()
                                        .id(entry.getKey())
                                        .status(entry.getValue())
                                        .build())
                        .toList())
                .build();

        return Response
                .status(207)
                .entity(response)
                .build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteTeams(final List<String> names) {
        final Set<String> uniqueNames = Set.copyOf(names);

        final List<String> deletedTeamNames = inJdbiTransaction(
                handle -> handle.attach(TeamDao.class).deleteTeamsByName(uniqueNames));

        final var response = BulkDeleteTeamsResponse.builder()
                .teams(uniqueNames.stream()
                        .<BulkDeleteTeamResult>map(
                                teamName -> BulkDeleteTeamResult.builder()
                                        .name(teamName)
                                        .status(deletedTeamNames.contains(teamName)
                                                ? "DELETED"
                                                : "DOES_NOT_EXIST")
                                        .build())
                        .peek(teamStatus -> {
                            if ("DELETED".equals(teamStatus.getStatus())) {
                                LOGGER.info(
                                        SecurityMarkers.SECURITY_AUDIT,
                                        "Team deleted: {}", teamStatus.getName());
                            }
                        })
                        .toList())
                .build();

        return Response
                .status(207)
                .entity(response)
                .build();
    }

    @Override
    public Response listTeamMemberships(final String team, final String user, final Integer limit, final String pageToken) {
        final Page<ListTeamMembershipsRow> membershipsPage = inJdbiTransaction(
                handle -> handle.attach(TeamDao.class).listTeamMembers(team, user, limit, pageToken));

        final var response = ListTeamMembershipsResponse.builder()
                .memberships(membershipsPage.items().stream()
                        .<ListTeamMembershipsResponseItem>map(
                                membershipRow -> ListTeamMembershipsResponseItem.builder()
                                        .teamName(membershipRow.teamName())
                                        .username(membershipRow.username())
                                        .build())
                        .toList())
                .pagination(createPaginationMetadata(uriInfo, membershipsPage))
                .build();

        return Response.ok(response).build();
    }

    @Override
    public Response createTeamMemberships(final BulkCreateTeamMembershipsRequest bulkRequest) {
        final long uniqueBulksRequestItemIds = bulkRequest.getMemberships().stream()
                .map(BulkCreateTeamMembershipsRequestItem::getId)
                .distinct()
                .count();
        if (uniqueBulksRequestItemIds < bulkRequest.getMemberships().size()) {
            throw new BadRequestException("Bulk request item IDs are not unique.");
        }

        final var statusByBulkItemId = new HashMap<String, String>(bulkRequest.getMemberships().size());

        final var allTeamNames = new HashSet<String>();
        final var allUsernames = new HashSet<String>();

        for (final BulkCreateTeamMembershipsRequestItem bulkItem : bulkRequest.getMemberships()) {
            allTeamNames.add(bulkItem.getTeamName());
            allUsernames.add(bulkItem.getUsername());
        }

        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final Map<String, Team> teamByName =
                        qm.getTeamsByName(allTeamNames).stream()
                                .collect(Collectors.toMap(Team::getName, Function.identity()));
                final Map<String, User> userByName =
                        qm.getUsersByName(allUsernames).stream()
                                .collect(Collectors.toMap(User::getUsername, Function.identity()));

                for (final BulkCreateTeamMembershipsRequestItem bulkItem : bulkRequest.getMemberships()) {
                    final Team team = teamByName.get(bulkItem.getTeamName());
                    final User user = userByName.get(bulkItem.getUsername());

                    if (team == null) {
                        statusByBulkItemId.put(bulkItem.getId(), "TEAM_DOES_NOT_EXIST");
                        continue;
                    } else if (user == null) {
                        statusByBulkItemId.put(bulkItem.getId(), "USER_DOES_NOT_EXIST");
                        continue;
                    } else if (team.getUsers().contains(user)) {
                        statusByBulkItemId.put(bulkItem.getId(), "ALREADY_EXISTS");
                        continue;
                    }

                    team.getUsers().add(user);
                    statusByBulkItemId.put(bulkItem.getId(), "CREATED");
                }
            });
        }

        final var response = BulkCreateTeamMembershipsResponse.builder()
                .memberships(statusByBulkItemId.entrySet().stream()
                        .<BulkCreateTeamMembershipsResponseItem>map(
                                entry -> BulkCreateTeamMembershipsResponseItem.builder()
                                        .id(entry.getKey())
                                        .status(entry.getValue())
                                        .build())
                        .toList())
                .build();

        return Response
                .status(207)
                .entity(response)
                .build();
    }

    @Override
    public Response deleteTeamMembership(final String team, final String user) {
        final boolean deleted = inJdbiTransaction(
                handle -> handle.attach(TeamDao.class).deleteTeamMembership(team, user));
        if (!deleted) {
            throw new NotFoundException();
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Team membership deleted: team={}, user={}", team, user);
        return Response.noContent().build();
    }
}
