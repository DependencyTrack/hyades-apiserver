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
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.event.MetricsPartitionCreateEvent;
import org.dependencytrack.metrics.Metrics;

import java.time.Duration;

import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * A {@link Subscriber} task that creates new partitions for the day.
 */
public class MetricsPartitionCreateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(MetricsPartitionCreateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final MetricsPartitionCreateEvent event) {
            try {
                executeWithLock(
                        getLockConfigForTask(MetricsPartitionCreateTask.class),
                        (LockingTaskExecutor.Task)() -> createPartitions());
            } catch (Throwable ex) {
                LOGGER.error("Error in acquiring lock and executing metrics partition create task", ex);
            }
        }
    }

    private void createPartitions() {
        LOGGER.info("Executing creation of partitions for Portfolio, Project and Dependency metrics");
        final long startTimeNs = System.nanoTime();
        try {
            Metrics.createMetricsPartitions();
        } finally {
            LOGGER.info("Completed creating metrics partitions in " + Duration.ofNanos(System.nanoTime() - startTimeNs));
        }
    }
}
