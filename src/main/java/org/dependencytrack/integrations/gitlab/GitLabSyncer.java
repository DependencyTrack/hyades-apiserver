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

import java.net.URISyntaxException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.locks.Lock;

import com.google.common.util.concurrent.Striped;

import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PermissionsSyncer;
import org.dependencytrack.model.Project;

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.model.OidcUser;
import alpine.model.Team;

public class GitLabSyncer extends AbstractIntegrationPoint implements PermissionsSyncer {

    private static final Logger LOGGER = Logger.getLogger(GitLabSyncer.class);
    private static final String INTEGRATIONS_GROUP = GITLAB_ENABLED.getGroupName();
    private static final String GENERAL_GROUP = GENERAL_BASE_URL.getGroupName();
    private static final String ROLE_CLAIM_PREFIX = "https://gitlab.org/claims/groups/";

    private final OidcUser user;
    private final Striped<Lock> locks;

    private GitLabClient gitLabClient;

    public GitLabSyncer(final OidcUser user, final GitLabClient gitlabClient) {
        this.locks = Striped.lock(128);
        this.user = user;
        this.gitLabClient = gitlabClient;
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
        try {
            List<GitLabProject> gitLabProjects = gitLabClient.getGitLabProjects();
            List<Project> projects = createProjects(gitLabProjects);
            List<Team> teams = projects.stream()
                    .flatMap(project -> createProjectTeams(project).stream())
                    .toList();
            List<String> teamNames = gitLabProjects.stream()
                    .map(gitLabProject -> "%s_%s".formatted(
                            gitLabProject.getFullPath(),
                            gitLabProject.getMaxAccessLevel().getStringValue().toString()))
                    .toList();

            qm.addUserToTeams(qm.getOidcUser(user.getUsername()), teamNames);

            teams = teams.stream().map(team -> qm.updateTeam(team)).toList();
            projects = projects.stream().map(project -> qm.updateProject(project, false)).toList();
        } catch (IOException | URISyntaxException ex) {
            LOGGER.error("An error occurred while querying GitLab GraphQL API", ex);
            handleException(LOGGER, ex);
        }
    }

    private List<Project> createProjects(List<GitLabProject> gitLabProjects) {
        List<Project> projects = new ArrayList<>();

        for (var gitLabProject : gitLabProjects) {
            final Lock lock = locks.get(gitLabProject.getFullPath());
            lock.lock();

            try {
                Project project = qm.getProject(gitLabProject.getFullPath(), null);

                if (project == null) {
                    LOGGER.debug("Creating project " + gitLabProject.getFullPath());

                    project = new Project();
                    project.setName(gitLabProject.getFullPath());
                    project = qm.persist(project);
                }

                project.setActive(project.getLastBomImport() != null);
                if (!project.isActive() && project.getInactiveSince() == null)
                    project.setInactiveSince(new Date());

                projects.add(qm.updateProject(project, false));
            } finally {
                lock.unlock();
            }
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

        for (var role : GitLabRole.values()) {
            final String teamName = "%s_%s".formatted(project.getName(), role.name());
            final Lock lock = locks.get(project.getName());
            lock.lock();

            try {
                Team team = qm.getTeam(teamName);
                team = team != null ? team : qm.createTeam(teamName);

                var permissions = gitLabClient.getRolePermissions(role).stream()
                        .map(rolePermission -> qm.getPermission(rolePermission.name()))
                        .filter(permission -> permission != null)
                        .distinct()
                        .toList();

                team.setPermissions(permissions);
                project.addAccessTeam(team);
                qm.updateProject(project, false);

                teams.add(team);
            } finally {
                lock.unlock();
            }
        }

        return teams;
    }

}
