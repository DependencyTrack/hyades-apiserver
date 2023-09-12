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
import alpine.common.util.SystemUtil;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import io.micrometer.core.instrument.Timer;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.apache.commons.collections4.ListUtils;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.LockProvider;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static java.time.Duration.ZERO;
import static org.dependencytrack.tasks.LockName.PORTFOLIO_METRICS_TASK_LOCK;


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
                LockProvider.executeWithLock(PORTFOLIO_METRICS_TASK_LOCK, (LockingTaskExecutor.Task)() -> updateMetrics(event.isForceRefresh()));
            } catch (Throwable ex) {
                LOGGER.error("Error in acquiring lock and executing portfolio metrics task", ex);
            }
        }
    }

    private void updateMetrics(final boolean forceRefresh) throws Exception {
        LOGGER.info("Executing portfolio metrics update");
        final Timer.Sample timerSample = Timer.start();

        try {
            if (forceRefresh) {
                LOGGER.info("Refreshing project metrics");
                refreshProjectMetrics();
            }

            Metrics.updatePortfolioMetrics();
        } finally {
            final long durationNanos = timerSample.stop(Timer
                    .builder("metrics_update")
                    .tag("target", "portfolio")
                    .register(alpine.common.metrics.Metrics.getRegistry()));
            LOGGER.info("Completed portfolio metrics update in " + Duration.ofNanos(durationNanos));
        }
    }

    private static void refreshProjectMetrics() throws Exception {
        try (final var qm = new QueryManager().withL2CacheDisabled()) {
            final PersistenceManager pm = qm.getPersistenceManager();

            LOGGER.debug("Fetching first " + BATCH_SIZE + " projects");
            LockConfiguration portfolioMetricsTaskConfig = LockProvider.getLockConfigurationByLockName(PORTFOLIO_METRICS_TASK_LOCK);
            List<ProjectProjection> activeProjects = fetchNextActiveProjectsPage(pm, null);
            long processStartTime = System.currentTimeMillis();
            while (!activeProjects.isEmpty()) {
                long startTimeOfBatch = System.currentTimeMillis();
                final long firstId = activeProjects.get(0).id();
                final long lastId = activeProjects.get(activeProjects.size() - 1).id();

                // Distribute the batch across at most MAX_CONCURRENCY events, and process them asynchronously.
                final List<List<ProjectProjection>> partitions = ListUtils.partition(activeProjects, MAX_CONCURRENCY);
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
                if(isLockToBeExtended(cumulativeDurationInMillis)) {
                    Duration extendLockByDuration = Duration.ofMillis(processDurationInMillis).plus(portfolioMetricsTaskConfig.getLockAtLeastFor());
                    LOGGER.debug("Extending lock duration by ms: " + extendLockByDuration);
                    LockExtender.extendActiveLock(extendLockByDuration, ZERO);
                }
                activeProjects = fetchNextActiveProjectsPage(pm, lastId);
            }
        }
    }

    private static List<ProjectProjection> fetchNextActiveProjectsPage(final PersistenceManager pm, final Long lastId) throws Exception {
        try (final Query<Project> query = pm.newQuery(Project.class)) {
            if (lastId == null) {
                query.setFilter("(active == null || active == true)");
            } else {
                query.setFilter("(active == null || active == true) && id < :lastId");
                query.setParameters(lastId);
            }
            query.setOrdering("id DESC");
            query.range(0, BATCH_SIZE);
            query.setResult("id, uuid");
            return List.copyOf(query.executeResultList(ProjectProjection.class));
        }
    }

    private static boolean isLockToBeExtended(long cumulativeDurationInMillis) {
        LockConfiguration lockConfiguration = LockProvider.getLockConfigurationByLockName(PORTFOLIO_METRICS_TASK_LOCK);
        return cumulativeDurationInMillis >=  (lockConfiguration.getLockAtMostFor().minus(lockConfiguration.getLockAtLeastFor())).toMillis() ? true : false;
    }

    public record ProjectProjection(long id, UUID uuid) {
    }

}
