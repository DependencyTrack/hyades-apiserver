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
import alpine.server.auth.PermissionRequired;
import org.dependencytrack.api.v2.TeamsApi;
import org.dependencytrack.api.v2.model.CreateTeamsRequest;
import org.dependencytrack.api.v2.model.DeleteTeamsResponse;
import org.dependencytrack.api.v2.model.DeleteTeamsResponseTeamsInner;
import org.dependencytrack.api.v2.model.GetTeamResponse;
import org.dependencytrack.api.v2.model.ListTeamMembersResponse;
import org.dependencytrack.api.v2.model.ListTeamMembersResponseItem;
import org.dependencytrack.api.v2.model.ListTeamsResponse;
import org.dependencytrack.api.v2.model.ListTeamsResponseItem;
import org.dependencytrack.api.v2.model.PaginationLinks;
import org.dependencytrack.api.v2.model.PaginationMetadata;
import org.dependencytrack.api.v2.model.UserType;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.TeamDao;
import org.dependencytrack.persistence.jdbi.TeamDao.ListTeamMembersRow;
import org.dependencytrack.persistence.jdbi.TeamDao.ListTeamsRow;
import org.dependencytrack.persistence.pagination.Page;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import java.util.List;
import java.util.Set;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

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
                                        .members(teamRow.members())
                                        .build())
                        .toList())
                .pagination(createPaginationMetadata(teamsPage))
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
    public Response createTeams(final CreateTeamsRequest createTeamRequest) {
        return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteTeams(final List<String> names) {
        final Set<String> uniqueNames = Set.copyOf(names);

        final List<String> deletedTeamNames = inJdbiTransaction(
                handle -> handle.attach(TeamDao.class).deleteTeamsByName(uniqueNames));

        final var teamStatuses = uniqueNames.stream()
                .<DeleteTeamsResponseTeamsInner>map(
                        teamName -> DeleteTeamsResponseTeamsInner.builder()
                                .name(teamName)
                                .status(deletedTeamNames.contains(teamName)
                                        ? DeleteTeamsResponseTeamsInner.StatusEnum.DELETED
                                        : DeleteTeamsResponseTeamsInner.StatusEnum.DOES_NOT_EXIST)
                                .build())
                .peek(teamStatus -> {
                    if (teamStatus.getStatus() == DeleteTeamsResponseTeamsInner.StatusEnum.DELETED) {
                        LOGGER.info(
                                SecurityMarkers.SECURITY_AUDIT,
                                "Team deleted: {}", teamStatus.getName());
                    }
                })
                .toList();

        return Response
                .status(207)
                .entity(DeleteTeamsResponse.builder()
                        .teams(teamStatuses)
                        .build())
                .build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response getTeamMembers(final String name, final Integer limit, final String pageToken) {
        final Page<ListTeamMembersRow> membersPage = inJdbiTransaction(handle -> {
            final var dao = handle.attach(TeamDao.class);
            if (!dao.doesTeamExist(name)) {
                throw new NotFoundException();
            }

            return dao.listTeamMembers(name, limit, pageToken);
        });

        final var response = ListTeamMembersResponse.builder()
                .users(membersPage.items().stream()
                        .<ListTeamMembersResponseItem>map(
                                userRow -> ListTeamMembersResponseItem.builder()
                                        .type(UserType.valueOf(userRow.type()))
                                        .name(userRow.name())
                                        .email(userRow.email())
                                        .build())
                        .toList())
                .pagination(createPaginationMetadata(membersPage))
                .build();

        return Response.ok(response).build();
    }

    // TODO: Move this to a central place so it's reusable.
    private PaginationMetadata createPaginationMetadata(final Page<?> page) {
        return PaginationMetadata.builder()
                .links(PaginationLinks.builder()
                        .self(uriInfo.getRequestUri())
                        .next(page.nextPageToken() != null ?
                                uriInfo.getRequestUriBuilder()
                                        .queryParam("page_token", page.nextPageToken())
                                        .build()
                                : null)
                        .build())
                .build();
    }

}
