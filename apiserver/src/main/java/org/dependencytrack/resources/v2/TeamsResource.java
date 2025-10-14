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
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.TeamsApi;
import org.dependencytrack.api.v2.model.CreateTeamMembershipRequest;
import org.dependencytrack.api.v2.model.CreateTeamRequest;
import org.dependencytrack.api.v2.model.GetTeamResponse;
import org.dependencytrack.api.v2.model.ListTeamMembershipsResponse;
import org.dependencytrack.api.v2.model.ListTeamMembershipsResponseItem;
import org.dependencytrack.api.v2.model.ListTeamsResponse;
import org.dependencytrack.api.v2.model.ListTeamsResponseItem;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.TeamDao;
import org.dependencytrack.persistence.jdbi.TeamDao.ListTeamMembershipsRow;
import org.dependencytrack.persistence.jdbi.TeamDao.ListTeamsRow;
import org.dependencytrack.persistence.pagination.Page;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.pagination.PageUtil.createPaginationMetadata;
import static org.dependencytrack.util.PersistenceUtil.isUniqueConstraintViolation;

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
    public Response createTeam(final CreateTeamRequest request) {
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final List<Permission> permissions =
                        qm.getPermissionsByName(request.getPermissions());

                final var team = new Team();
                team.setName(request.getName());
                team.setPermissions(permissions);
                qm.persist(team);
            });
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException("Team already exists", e);
            }

            throw e;
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Team created: {}", request.getName());
        return Response
                .created(uriInfo.getBaseUriBuilder()
                        .path("/teams")
                        .path(request.getName())
                        .build())
                .build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response deleteTeam(final String name) {
        final List<String> deletedTeamNames = inJdbiTransaction(
                handle -> handle.attach(TeamDao.class).deleteTeamsByName(List.of(name)));
        if (deletedTeamNames.isEmpty()) {
            throw new NotFoundException();
        }

        LOGGER.info(SecurityMarkers.SECURITY_AUDIT, "Team deleted: {}", name);
        return Response.noContent().build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
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
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
    public Response createTeamMembership(final CreateTeamMembershipRequest request) {
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                final Team team = qm.getTeam(request.getTeamName());
                if (team == null) {
                    throw new NotFoundException();
                }

                final User user = qm.getUser(request.getUsername());
                if (user == null) {
                    throw new NotFoundException();
                }

                team.getUsers().add(user);
                user.getTeams().add(team);
            });
        } catch (RuntimeException e) {
            if (isUniqueConstraintViolation(e)) {
                throw new AlreadyExistsException("Team membership already exists", e);
            }

            throw e;
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Team membership created: team={}, user={}",
                request.getTeamName(),
                request.getUsername());
        return Response.created(null).build();
    }

    @Override
    @PermissionRequired(Permissions.Constants.ACCESS_MANAGEMENT)
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
