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
import alpine.common.util.SystemUtil;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.LockProvider.isTaskLockToBeExtended;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * A {@link Subscriber} task that updates portfolio metrics.
 *
 * @since 4.6.0
 */
public class PortfolioMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(PortfolioMetricsUpdateTask.class);
    private static final int MAX_CONCURRENCY = SystemUtil.getCpuCores();
    private static final int BATCH_SIZE = MAX_CONCURRENCY * 100;

    @Override
    public void inform(final Event e) {
        if (e instanceof final PortfolioMetricsUpdateEvent event) {
            try {
                executeWithLock(
                        getLockConfigForTask(PortfolioMetricsUpdateTask.class),
                        (LockingTaskExecutor.Task)() -> updateMetrics(event.isForceRefresh()));
            } catch (Throwable ex) {
                LOGGER.error("Error in acquiring lock and executing portfolio metrics task", ex);
            }
        }
    }

    private void updateMetrics(final boolean forceRefresh) throws Exception {
        LOGGER.info("Executing portfolio metrics update");
        final long startTimeNs = System.nanoTime();

        try {
            if (forceRefresh) {
                LOGGER.info("Refreshing project metrics");
                refreshProjectMetrics();
            }

            Metrics.updatePortfolioMetrics();
        } finally {
            LOGGER.info("Completed portfolio metrics update in " + Duration.ofNanos(System.nanoTime() - startTimeNs));
        }
    }

    private static void refreshProjectMetrics() throws Exception {
        try (final var qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.debug("Fetching first " + BATCH_SIZE + " projects");
            LockConfiguration portfolioMetricsTaskConfig = getLockConfigForTask(PortfolioMetricsUpdateTask.class);
            List<ProjectProjection> activeProjects = fetchNextActiveProjectsPage(pm, null);
            long processStartTime = System.currentTimeMillis();
            while (!activeProjects.isEmpty()) {
                long startTimeOfBatch = System.currentTimeMillis();
                final long firstId = activeProjects.get(0).id();
                final long lastId = activeProjects.get(activeProjects.size() - 1).id();

                // Distribute the batch across at most MAX_CONCURRENCY events, and process them asynchronously.
                final List<List<ProjectProjection>> partitions = partition(activeProjects, MAX_CONCURRENCY);
                final var countDownLatch = new CountDownLatch(partitions.size());

                for (final List<ProjectProjection> partition : partitions) {
                    final var partitionEvent = new CallbackEvent(() -> {
                        for (final ProjectProjection project : partition) {
                            new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.uuid()));
                        }
                    });

                    final var countDownEvent = new CallbackEvent(countDownLatch::countDown);
                    Event.dispatch(partitionEvent
                            .onSuccess(countDownEvent)
                            .onFailure(countDownEvent));
                }

                LOGGER.debug("Waiting for metrics updates for projects " + firstId + "-" + lastId + " to complete");
                if (!countDownLatch.await(15, TimeUnit.MINUTES)) {
                    // Depending on the system load, it may take a while for the queued events
                    // to be processed. And depending on how large the projects are, it may take a
                    // while for the processing of the respective event to complete.
                    // It is unlikely though that either of these situations causes a block for
                    // over 15 minutes. If that happens, the system is under-resourced.
                    LOGGER.warn("Updating metrics for projects " + firstId + "-" + lastId +
                            " took longer than expected (15m); Proceeding with potentially stale data");
                }
                LOGGER.debug("Completed metrics updates for projects " + firstId + "-" + lastId);
                LOGGER.debug("Fetching next " + BATCH_SIZE + " projects");
                long now = System.currentTimeMillis();
                long processDurationInMillis = now - startTimeOfBatch;
                long cumulativeDurationInMillis = now - processStartTime;
                //extend the lock for the duration of process
                //initial duration of portfolio metrics can be set to 20min.
                //No thread calculating metrics would be executing for more than 15min.
                //lock can only be extended if lock until is held for time after current db time
                if(isTaskLockToBeExtended(cumulativeDurationInMillis, PortfolioMetricsUpdateTask.class)) {
                    Duration extendLockByDuration = Duration.ofMillis(processDurationInMillis).plus(portfolioMetricsTaskConfig.getLockAtLeastFor());
                    LOGGER.debug("Extending lock duration by ms: " + extendLockByDuration);
                    LockExtender.extendActiveLock(extendLockByDuration, portfolioMetricsTaskConfig.getLockAtLeastFor());
                }
                activeProjects = fetchNextActiveProjectsPage(pm, lastId);
            }
        }
    }

    public record ProjectProjection(long id, UUID uuid) {
    }

    private static List<ProjectProjection> fetchNextActiveProjectsPage(final PersistenceManager pm, final Long lastId) throws Exception {
        try (final Query<Project> query = pm.newQuery(Project.class)) {
            if (lastId == null) {
                query.setFilter("inactiveSince == null");
            } else {
                query.setFilter("inactiveSince == null && id < :lastId");
                query.setParameters(lastId);
            }
            query.setOrdering("id DESC");
            query.range(0, BATCH_SIZE);
            query.setResult("id, uuid");
            return List.copyOf(query.executeResultList(ProjectProjection.class));
        }
    }

    static <T> List<List<T>> partition(final List<T> list, int numPartitions) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }

        final int listSize = list.size();
        final var partitions = new ArrayList<List<T>>(numPartitions);
        int partitionSize = (int) Math.ceil((double) listSize / numPartitions);

        int i = 0, elementsLeft = listSize;
        while (i < listSize && numPartitions != 0) {
            partitions.add(list.subList(i, i + partitionSize));
            i = i + partitionSize;
            elementsLeft = elementsLeft - partitionSize;
            partitionSize = (int) Math.ceil((double) elementsLeft / --numPartitions);
        }

        return partitions;
    }

}
