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
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;

public class GitHubAdvisoryMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(GitHubAdvisoryMirrorTask.class);
    private final boolean isEnabled;
    private String accessToken;

    public GitHubAdvisoryMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
            final ConfigProperty accessToken = qm.getConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getGroupName(), VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN.getPropertyName());
            if (accessToken != null) {
                this.accessToken = accessToken.getPropertyValue();
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof GitHubAdvisoryMirrorEvent && this.isEnabled) {
            if (this.accessToken != null) {
                LOGGER.info("Starting GitHub Advisory mirroring task");
                new KafkaEventDispatcher().dispatchEvent(new GitHubAdvisoryMirrorEvent()).join();
            } else {
                LOGGER.warn("GitHub Advisory mirroring is enabled, but no personal access token is configured. Skipping.");
            }
        }
    }
}
