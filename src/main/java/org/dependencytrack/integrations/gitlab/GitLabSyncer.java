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

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.model.Team;
import alpine.model.UserPrincipal;
import alpine.server.auth.AuthorizationTokenCookie;
import alpine.server.auth.JsonWebToken;

import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PermissionsSyncer;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.UserResource;

import java.net.URL;
import java.security.Principal;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_APP_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_URL;

public class GitLabSyncer extends AbstractIntegrationPoint implements PermissionsSyncer {

    private static final Logger LOGGER = Logger.getLogger(GitLabSyncer.class);
    private static final String INTEGRATIONS_GROUP = GITLAB_ENABLED.getGroupName();
    private static final String GENERAL_GROUP = GENERAL_BASE_URL.getGroupName();
    private static final String ROLE_CLAIM_PREFIX = "https://gitlab.org/claims/groups/";
    private static final String ROLE_DEVELOPER = "developer";
    private static final String ROLE_MAINTAINER = "maintainer";
    private static final String ROLE_OWNER = "owner";

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
        return enabled != null && Boolean.valueOf(enabled.getPropertyValue());
    }

    @Override
    public void synchronize(final Project project) {
        final ConfigProperty gitLabAppId = qm.getConfigProperty(INTEGRATIONS_GROUP, GITLAB_APP_ID.getPropertyName());
        final ConfigProperty gitLabToken = qm.getConfigProperty(INTEGRATIONS_GROUP, GITLAB_TOKEN.getPropertyName());
        final ConfigProperty gitLabUrl = qm.getConfigProperty(INTEGRATIONS_GROUP, GITLAB_URL.getPropertyName());
        final ConfigProperty baseUrl = qm.getConfigProperty(GENERAL_GROUP, GENERAL_BASE_URL.getPropertyName());

        UserPrincipal principal = (new UserResource()).getSelf().readEntity(UserPrincipal.class);
        String token = new JsonWebToken().createToken((Principal) principal);
        AuthorizationTokenCookie cookie = new AuthorizationTokenCookie(token);
        String state = cookie.toString();

        try (final QueryManager qm = new QueryManager()) {
            final GitLabClient client = new GitLabClient(this, new URL(gitLabUrl.getPropertyValue()));

            // Send request to GitLab API to get OIDC user's groups
            client.getGitLabGroupClaims(gitLabToken.getPropertyValue(),
                    gitLabAppId.getPropertyValue(),
                    baseUrl.getPropertyValue(),
                    state);

            // TODO: Get effective access for groups

            // Create team and add to project
            for (String s : new String[] { ROLE_DEVELOPER, ROLE_MAINTAINER, ROLE_OWNER }) {
                final String teamName = String.join("-", project.getName(), s);

                Team team = qm.getTeam(teamName);
                team = team != null ? team : qm.createTeam(teamName, false);

                // TODO: set permissions for team
                // team.setPermissions(null);

                project.addAccessTeam(team);
            }
        } catch (Exception e) {
            LOGGER.error("An error occurred attempting to synchronize GitLab groups", e);
            handleException(LOGGER, e);
        }
    }
}
