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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.persistence.QueryManager;

import java.time.Duration;
import java.util.UUID;

/**
 * A {@link Subscriber} task that updates {@link Project} metrics.
 *
 * @since 4.6.0
 */
public class ProjectMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final ProjectMetricsUpdateEvent event) {
            WorkflowState metricsUpdateState;
            try (final var qm = new QueryManager()) {
                metricsUpdateState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), WorkflowStep.METRICS_UPDATE);
                try {
                    updateMetrics(event.getUuid());
                    qm.updateWorkflowStateToComplete(metricsUpdateState);
                } catch (Exception ex) {
                    qm.updateWorkflowStateToFailed(metricsUpdateState, ex.getMessage());
                    LOGGER.error("An unexpected error occurred while updating metrics for project " + event.getUuid(), ex);
                }
            }
        }
    }

    private static void updateMetrics(final UUID uuid) {
        LOGGER.debug("Executing metrics update for project " + uuid);
        final Timer.Sample timerSample = Timer.start();

        try {
            Metrics.updateProjectMetrics(uuid);
        } finally {
            final long durationNanos = timerSample.stop(Timer
                    .builder("metrics_update")
                    .tag("target", "project")
                    .register(alpine.common.metrics.Metrics.getRegistry()));
            LOGGER.debug("Completed metrics update for project " + uuid + " in " + Duration.ofNanos(durationNanos));
        }
    }

}
