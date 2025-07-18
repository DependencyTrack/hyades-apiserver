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

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;

import org.dependencytrack.integrations.gitlab.GitLabIntegrationStateChanger;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;

import org.dependencytrack.event.GitLabIntegrationStateEvent;

public class GitLabIntegrationStateTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitLabIntegrationStateTask.class);
    private final boolean isEnabled;

    public GitLabIntegrationStateTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(GITLAB_ENABLED.getGroupName(), GITLAB_ENABLED.getPropertyName());

            this.isEnabled = enabled != null && Boolean.parseBoolean(enabled.getPropertyValue());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event event) {
        if (!(event instanceof GitLabIntegrationStateEvent)) {
            return;
        }

        LOGGER.info("Starting GitLab state change task");

        try (QueryManager qm = new QueryManager()) {
            GitLabIntegrationStateChanger stateChanger = new GitLabIntegrationStateChanger();
            stateChanger.setQueryManager(qm);
            stateChanger.setState(this.isEnabled);
        }

        LOGGER.info("GitLab state change complete");
    }

}
