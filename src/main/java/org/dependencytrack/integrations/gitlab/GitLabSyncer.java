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

import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.integrations.PermissionsSyncer;
import org.dependencytrack.model.Project;

import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;

public class GitLabSyncer extends AbstractIntegrationPoint implements PermissionsSyncer {

    private static final Logger LOGGER = Logger.getLogger(GitLabSyncer.class);
    private static final String INTEGRATIONS_GROUP = GITLAB_ENABLED.getGroupName();
    private static final String GENERAL_GROUP = GENERAL_BASE_URL.getGroupName();
    private static final String ROLE_CLAIM_PREFIX = "https://gitlab.org/claims/groups/";
    private static final String ROLE_DEVELOPER = "developer";
    private static final String ROLE_MAINTAINER = "maintainer";
    private static final String ROLE_OWNER = "owner";

    private final String accessToken;

    public GitLabSyncer(final String accessToken) {
        this.accessToken = accessToken;
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
    public void synchronize(final Project project) {

    }

}
