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
package org.dependencytrack.integrations.gitlab;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PermissionsSyncer;
import org.dependencytrack.model.Project;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.model.OidcUser;
import alpine.model.Permission;
import alpine.model.Team;

public class GitLabSyncer extends AbstractIntegrationPoint implements PermissionsSyncer {

    private static final Logger LOGGER = Logger.getLogger(GitLabSyncer.class);
    private static final String INTEGRATIONS_GROUP = GITLAB_ENABLED.getGroupName();
    private static final String GENERAL_GROUP = GENERAL_BASE_URL.getGroupName();
    private static final String ROLE_CLAIM_PREFIX = "https://gitlab.org/claims/groups/";

    private final String accessToken;
    private final OidcUser user;
    private GitLabClient gitLabClient;

    public GitLabSyncer(final String accessToken, final OidcUser user) {
        this.accessToken = accessToken;
        this.user = user;
    }

    public String getAccessToken() {
        return accessToken;
    }

    @Override
    public String name() {
        return "GitLab";
    }

    @Override
    public String description() {
        return "Synchronizes user permissions from connected GitLab instance";
    }

    @Override
    public boolean isEnabled() {
        final ConfigProperty enabled = qm.getConfigProperty(INTEGRATIONS_GROUP, GITLAB_ENABLED.getPropertyName());

        return enabled != null && Boolean.parseBoolean(enabled.getPropertyValue());
    }

    @Override
    public void synchronize() {
        final URI gitLabUrl = URI.create(Config.getInstance().getProperty(Config.AlpineKey.OIDC_ISSUER));
        gitLabClient = new GitLabClient(this, gitLabUrl, accessToken);

        List<GitLabProject> gitLabProjects = gitLabClient.getGitLabProjects();
        List<Project> projects = createProjects(gitLabProjects);

        for (Project project : projects) {
            List<Team> teams = createProjectTeams(project);

            for (Team team : teams) {
                List<OidcUser> teamUsers = team.getOidcUsers();
                if (!teamUsers.contains(user)) {
                    teamUsers.add(user);
                    team.setOidcUsers(teamUsers);
                }

                qm.updateTeam(team);
            }
        }
    }

    private List<Project> createProjects(List<GitLabProject> gitLabProjects) {
        List<Project> projects = new ArrayList<>();

        for (GitLabProject gitLabProject : gitLabProjects) {
            Project project = qm.getProject(gitLabProject.getFullPath(), null);

            if (project == null) {
                LOGGER.debug("Creating project " + gitLabProject.getFullPath());

                project = new Project();
                project.setName(gitLabProject.getFullPath());
                project = qm.persist(project);
            }

            projects.add(project);
        }

        return projects;
    }

    /**
     * Create teams for a Dependency-Track project representing a project within
     * GitLab.
     *
     * @param project Dependency-Track project representing a GitLab project
     * @return the Dependency-Track teams for the project
     */
    private List<Team> createProjectTeams(Project project) {
        List<Team> teams = new ArrayList<>();

        for (GitLabRole role : GitLabRole.values()) {
            final String teamName = "%s_%s".formatted(project.getName(), role.name());

            Team team = qm.getTeam(teamName);
            team = team != null ? team : qm.createTeam(teamName);

            List<Permissions> rolePermissions = gitLabClient.getRolePermissions(role);
            List<Permission> permissions = new ArrayList<>(team.getPermissions());

            for (Permissions rolePermission : rolePermissions) {
                Permission permission = qm.getPermission(rolePermission.name());
                if (permission != null && !permissions.contains(permission))
                    permissions.add(permission);
            }

            team.setPermissions(permissions);
            project.addAccessTeam(team);
            qm.updateProject(project, false);

            teams.add(team);
        }

        return teams;
    }

}