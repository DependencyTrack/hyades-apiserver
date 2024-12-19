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
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.workflow.framework.ActivityRunContext;
import org.dependencytrack.workflow.framework.ActivityRunner;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

/**
 * A {@link Subscriber} task that updates {@link Project} metrics.
 *
 * @since 4.6.0
 */
@Activity(name = "update-project-metrics")
public class ProjectMetricsUpdateTask implements ActivityRunner<UpdateProjectMetricsArgs, Void>, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsUpdateTask.class);

    @Override
    public Optional<Void> run(final ActivityRunContext<UpdateProjectMetricsArgs> ctx) throws Exception {
        final UpdateProjectMetricsArgs args = ctx.argument().orElseThrow();

        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, args.getProject().getUuid());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, args.getProject().getName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, args.getProject().getVersion())) {
            LOGGER.info("Executing metrics update");

            useJdbiHandle(handle -> handle
                    .createCall("CALL \"UPDATE_PROJECT_METRICS\"(:uuid)")
                    .bind("uuid", UUID.fromString(args.getProject().getUuid()))
                    .setQueryTimeout(30) // TODO: Set this globally?
                    .invoke());
        }

        return Optional.empty();
    }

    @Override
    public void inform(final Event e) {
        if (e instanceof final ProjectMetricsUpdateEvent event) {
            try (final var qm = new QueryManager();
                 var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, event.getUuid().toString())) {
                final WorkflowState metricsUpdateState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), WorkflowStep.METRICS_UPDATE);
                try {
                    updateMetrics(event.getUuid());
                    qm.updateWorkflowStateToComplete(metricsUpdateState);
                } catch (RuntimeException ex) {
                    qm.updateWorkflowStateToFailed(metricsUpdateState, ex.getMessage());
                    LOGGER.error("An unexpected error occurred while updating metrics", ex);
                }
            }
        }
    }

    private static void updateMetrics(final UUID uuid) {
        LOGGER.debug("Executing metrics update");
        final long startTimeNs = System.nanoTime();
        try {
            Metrics.updateProjectMetrics(uuid);
        } finally {
            LOGGER.debug("Completed metrics update in %s".formatted(Duration.ofNanos(System.nanoTime() - startTimeNs)));
        }
    }

}
