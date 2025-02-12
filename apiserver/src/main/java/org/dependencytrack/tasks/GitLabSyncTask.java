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

import org.dependencytrack.event.GitLabSyncEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_TOKEN;

public class GitLabSyncTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitLabSyncTask.class);
    private final boolean isEnabled;
    private String accessToken;

    public GitLabSyncTask() {
        final String groupName = GITLAB_ENABLED.getGroupName();

        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(groupName, GITLAB_ENABLED.getPropertyName());
            final ConfigProperty accessToken = qm.getConfigProperty(groupName, GITLAB_TOKEN.getPropertyName());

            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
            this.accessToken = accessToken != null ? accessToken.getPropertyValue() : "";
        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (!(e instanceof GitLabSyncEvent && this.isEnabled)) {
            return;
        }

        if (this.accessToken == null) {
            LOGGER.warn("GitLab syncing is enabled, but no personal access token is configured. Skipping.");
            return;
        }

        LOGGER.info("Starting GitLab sync task");
        new KafkaEventDispatcher().dispatchEvent(new GitLabSyncEvent()).join();
    }
}
