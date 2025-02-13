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
package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import alpine.model.OidcUser;

import org.dependencytrack.event.GitLabSyncEvent;
import org.dependencytrack.integrations.gitlab.GitLabClient;
import org.dependencytrack.integrations.gitlab.GitLabSyncer;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;

import java.net.URI;

public class GitLabSyncTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitLabSyncTask.class);
    private final boolean isEnabled;

    public GitLabSyncTask() {
        final String groupName = GITLAB_ENABLED.getGroupName();

        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(groupName, GITLAB_ENABLED.getPropertyName());

            this.isEnabled = enabled != null && Boolean.parseBoolean(enabled.getPropertyValue());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event event) {
        if (!(event instanceof GitLabSyncEvent && this.isEnabled)) {
            return;
        }

        GitLabSyncEvent gitLabSyncEvent = (GitLabSyncEvent) event;

        String accessToken = gitLabSyncEvent.getAccessToken();
        if (accessToken == null || accessToken.isEmpty()) {
            LOGGER.warn("GitLab syncing is enabled, but no access token was provided. Skipping.");
            return;
        }

        OidcUser user = gitLabSyncEvent.getUser();
        if (user == null) {
            LOGGER.warn("GitLab syncing is enabled, but no authenticated user was provided. Skipping.");
            return;
        }

        LOGGER.info("Starting GitLab sync task");

        try (QueryManager qm = new QueryManager()) {
            final URI gitLabUrl = URI.create(Config.getInstance().getProperty(Config.AlpineKey.OIDC_ISSUER));
            GitLabClient gitLabClient = new GitLabClient(gitLabUrl, accessToken);
            GitLabSyncer syncer = new GitLabSyncer(accessToken, user, gitLabClient);
            syncer.setQueryManager(qm);
            syncer.synchronize();
        }

        // TODO:
        // - [X] Assign authenticated OIDC user the VIEW_PORTFOLIO permission
        // - [ ] Get user GitLab project memberships (use alpine.security.crypto.DataEncryption for request)
        // - [X] Create Dependency-Track hierarchical project structure for user's GitLab projects
        // - [X] Create Dependency-Track teams such as <GitLab project name>-maintainer
        // - [ ] Come up with a set of Dependency-Track project permissions per GitLab role
        // - [ ] Assign Dependency-Track permissions (TBD) to teams based on GitLab role
        // - [ ] Map user OIDC groups to Dependency-Track teams
        // - [ ] Configure portfolio access control (map team to project access)
    }

}
