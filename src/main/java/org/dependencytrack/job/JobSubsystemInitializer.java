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
package org.dependencytrack.job;

import alpine.common.logging.Logger;
import org.dependencytrack.tasks.NistMirrorTask;
import org.dependencytrack.tasks.metrics.PortfolioMetricsUpdateTask;
import org.dependencytrack.tasks.metrics.VulnerabilityMetricsUpdateTask;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class JobSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(JobSubsystemInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing job manager");
        final var jobManager = JobManager.getInstance();

        jobManager.scheduleAll(List.of(
                new NewJobSchedule("nvd-mirroring", "* * * * *", "mirror-nvd", null, null),
                new NewJobSchedule("portfolio-metrics-update", "* * * * *", "update-metrics-portfolio", null, null),
                new NewJobSchedule("vuln-metrics-update", "* * * * *", "update-metrics-vulns", null, null)));

        final SecureRandom random = new SecureRandom();
        jobManager.registerWorker(Set.of("consume-bom"), 5, new RandomlyFailingJobWorker(random));
        jobManager.registerWorker(Set.of("process-bom"), 5, new RandomlyFailingJobWorker(random));
        jobManager.registerWorker(Set.of("analyze-vulns-project"), 3, new RandomlyFailingJobWorker(random));
        jobManager.registerWorker(Set.of("evaluate-policies-project"), 3, new RandomlyFailingJobWorker(random));
        jobManager.registerWorker(Set.of("update-metrics-project"), 3, new RandomlyFailingJobWorker(random));

        jobManager.registerWorker(Set.of("mirror-nvd"), 1, new NistMirrorTask());
        jobManager.registerWorker(Set.of("update-metrics-portfolio"), 1, new PortfolioMetricsUpdateTask());
        jobManager.registerWorker(Set.of("update-metrics-vulns"), 1, new VulnerabilityMetricsUpdateTask());
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down job manager");

        try {
            JobManager.getInstance().close();
        } catch (IOException e) {
            LOGGER.warn("Graceful shutdown of job manager failed", e);
        }
    }

    private static class RandomlyFailingJobWorker implements JobWorker {

        private static final Logger LOGGER = Logger.getLogger(RandomlyFailingJobWorker.class);
        private final SecureRandom random;

        private RandomlyFailingJobWorker(final SecureRandom random) {
            this.random = random;
        }

        @Override
        public Optional<JobResult> process(final QueuedJob job) throws Exception {
            LOGGER.debug("Processing " + job);

            Thread.sleep(random.nextInt(10, 1000));

            if (random.nextDouble() > 0.2) {
                throw new IllegalStateException("Oh no!");
            }

            return Optional.empty();
        }

    }

}
