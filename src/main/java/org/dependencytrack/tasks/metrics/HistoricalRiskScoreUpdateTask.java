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
import org.apache.commons.collections4.ListUtils;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.HistoricalRiskScoreUpdateEvent;
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

import static org.dependencytrack.tasks.LockName.PORTFOLIO_METRICS_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.isLockToBeExtended;


/**
 * A {@link Subscriber} task that updates portfolio metrics.
 *
 * @since 4.6.0
 */
public class HistoricalRiskScoreUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(PortfolioMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final HistoricalRiskScoreUpdateEvent event) {
            try {
                LockProvider.executeWithLock(PORTFOLIO_METRICS_TASK_LOCK, (LockingTaskExecutor.Task)() -> updateMetrics(event.isForceRefresh()));
            } catch (Throwable ex) {
                LOGGER.error("Error in acquiring lock and executing portfolio metrics task", ex);
            }
        }
    }

    private void updateMetrics(final boolean weightHistoryEnabled) throws Exception {
        LOGGER.info("Executing historical risk score metrics update");
        final long startTimeNs = System.nanoTime();

        try {
            if (weightHistoryEnabled) {
                LOGGER.info("Refreshing historical risk score metrics");
                Metrics.updateHistoricalRiskScores();
            }

            Metrics.updatePortfolioMetrics();
        } finally {
            LOGGER.info("Completed historical risk score metrics update in " + Duration.ofNanos(System.nanoTime() - startTimeNs));
        }
    }

    public record ProjectProjection(long id, UUID uuid) {
    }

}
