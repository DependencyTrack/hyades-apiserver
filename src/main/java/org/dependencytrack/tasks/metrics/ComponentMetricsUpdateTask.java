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
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.persistence.QueryManager;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.dependencytrack.model.WorkflowStep.METRICS_UPDATE;

/**
 * A {@link Subscriber} task that updates {@link Component} metrics.
 *
 * @since 4.6.0
 */
public class ComponentMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ComponentMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final ComponentMetricsUpdateEvent event) {
            LOGGER.debug("Executing metrics update for component " + event.getUuid());
            final Timer.Sample timerSample = Timer.start();
            WorkflowState metricsUpdateState = null;
            try (final var qm = new QueryManager()) {
               metricsUpdateState = qm.updateStartTimeIfWorkflowStateExists(event.getChainIdentifier(), METRICS_UPDATE);
                try {
                    Metrics.updateComponentMetrics(event.getUuid());
                    qm.updateWorkflowStateToComplete(metricsUpdateState);
                } catch (Exception ex) {
                    qm.updateWorkflowStateToFailed(metricsUpdateState, ex.getMessage());
                    LOGGER.error("An unexpected error occurred while updating metrics of component " + event.getUuid(), ex);
                }
            } finally {
                final long durationNanos = timerSample.stop(Timer
                        .builder("metrics_update")
                        .tag("target", "component")
                        .register(alpine.common.metrics.Metrics.getRegistry()));
                LOGGER.debug("Completed metrics update for component " + event.getUuid() + " in " + Duration.ofNanos(durationNanos));
            }
        }
    }
}
