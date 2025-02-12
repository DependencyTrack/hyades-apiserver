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

import alpine.Config;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.net.URI;

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PermissionsSyncer;
import org.dependencytrack.model.Project;

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
    private static final URI baseURL = URI.create(Config.getInstance().getProperty(Config.AlpineKey.OIDC_ISSUER));

    private final String accessToken;
    private final OidcUser user;

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
        GitLabClient gitLabClient = new GitLabClient(this, baseURL, this.accessToken);
    
        List<GitLabProject> projects = gitLabClient.getGitLabProjects();

        createProjectStructure(projects);
    }

    /**
     * Create hierarchical project structure for user's GitLab projects.
     *
     * For example, if a GitLab project path is org/group/subgroup/project, then
     * the following Dependency-Track projects will be created:
     * <ul>
     * <li>org
     * <li>org/group
     * <li>org/group/subgroup
     * <li>org/group/subgroup/project
     * </ul>
     *
     * @param projects the list of GitLab project names available to the user
     */
    public void createProjectStructure(List<GitLabProject> projects) {

        for (GitLabProject project : projects) {
            Project parent = null;
            List<String> toCreate = getProjectNames(project.getFullPath());

            for (String group : toCreate) {
                LOGGER.debug("Creating project " + group);

                Project existingProject = qm.getProject(group, null);
                if (existingProject != null) {
                    parent = existingProject;
                    continue;
                }

                parent = qm.createProject(group, null, null, null, parent, null, null, false);
            }

            // Set access teams for last project created (the full path of the GitLab project)
            List<Team> teams = createProjectTeams(parent);

            List<Team> userTeams = user.getTeams();
            for (Team team : userTeams) {
                if (!teams.contains(team)) {
                    userTeams.add(team);
                }
            }

            user.setTeams(userTeams);
        }
    }

    /**
     * Create teams for a Dependency-Track project representing a project within
     * GitLab.
     *
     * @param project Dependency-Track project representing a GitLab project
     * @return the Dependency-Track teams for the project
     */
    public List<Team> createProjectTeams(Project project) {
        List<Team> teams = new ArrayList<>();

        for (GitLabRole role : GitLabRole.values()) {
            final String teamName = "%s_%s".formatted(project.getName(), role.name());

            Team team = qm.getTeam(teamName);
            team = team != null ? team : qm.createTeam(teamName);

            List<Permission> permissions = team.getPermissions();
            Permission viewPermission = qm.getPermission(Permissions.Constants.VIEW_PORTFOLIO);

            if (!permissions.contains(viewPermission)) {
                permissions.add(viewPermission);
            }

            team.setPermissions(permissions);

            project.addAccessTeam(team);
            teams.add(team);
        }

        return teams;
    }

    /**
     * Generate list of hierarchical projects to be created to represent user's
     * GitLab projects.
     *
     * For example, if a GitLab project path is org/group/subgroup/project, then
     * the following project names will be returned:
     * <ul>
     * <li>org
     * <li>org/group
     * <li>org/group/subgroup
     * <li>org/group/subgroup/project
     * </ul>
     *
     * @param project the GitLab project name
     * @return the project names to be created
     */
    public List<String> getProjectNames(String project) {
        List<String> projects = new ArrayList<>();
        List<String> parts = Arrays.asList(project.split("/"));

        for (int i = 0; i < parts.size(); i++) {
            projects.add(String.join("/", parts.subList(0, i + 1)));
        }

        return projects;
    }

}