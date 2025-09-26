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
package org.dependencytrack.workflow;

import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.failure.TerminalApplicationFailureException;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

import static org.dependencytrack.metrics.Metrics.updateProjectMetrics;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@Activity(name = "update-project-metrics")
public final class UpdateProjectMetricsActivity implements ActivityExecutor<ProjectIdentity, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateProjectMetricsActivity.class);

    @Override
    public Void execute(
            final @NonNull ActivityContext ctx,
            final ProjectIdentity projectIdentity) throws Exception {
        if (projectIdentity == null) {
            throw new TerminalApplicationFailureException("No project provided", null);
        }

        final UUID projectUuid;
        try {
            projectUuid = UUID.fromString(projectIdentity.getUuid());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("Project UUID is invalid", e);
        }

        final boolean doesProjectExist = withJdbiHandle(
                handle -> handle.attach(ProjectDao.class).getProjectId(projectUuid) != null);
        if (!doesProjectExist) {
            throw new TerminalApplicationFailureException("Project does not exist", null);
        }

        LOGGER.info("Updating metrics of project {}", projectUuid);
        updateProjectMetrics(projectUuid);

        return null;
    }

}
