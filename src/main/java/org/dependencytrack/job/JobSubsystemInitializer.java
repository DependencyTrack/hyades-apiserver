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
import org.dependencytrack.job.persistence.PolledJob;
import org.dependencytrack.proto.job.v1alpha1.JobResult;
import org.dependencytrack.tasks.NistMirrorTask;
import org.dependencytrack.tasks.metrics.PortfolioMetricsUpdateTask;
import org.dependencytrack.tasks.metrics.VulnerabilityMetricsUpdateTask;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

public class JobSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(JobSubsystemInitializer.class);

    private JobEngine jobEngine;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing job engine");
        jobEngine = JobEngine.getInstance();
        jobEngine.start();

        jobEngine.scheduleAll(List.of(
                new NewJobSchedule("nvd-mirroring", "* * * * *", "mirror-nvd", null, null),
                new NewJobSchedule("portfolio-metrics-update", "* * * * *", "update-metrics-portfolio", null, null),
                new NewJobSchedule("vuln-metrics-update", "* * * * *", "update-metrics-vulns", null, null)));

        final SecureRandom random = new SecureRandom();
        jobEngine.registerWorker("consume-bom", 5, new RandomlyFailingJobWorker(random));
        jobEngine.registerWorker("process-bom", 5, new RandomlyFailingJobWorker(random));
        jobEngine.registerWorker("analyze-vulns-project", 3, new RandomlyFailingJobWorker(random));
        jobEngine.registerWorker("evaluate-policies-project", 3, new RandomlyFailingJobWorker(random));
        jobEngine.registerWorker("update-metrics-project", 3, new RandomlyFailingJobWorker(random));

        jobEngine.registerWorker("mirror-nvd", 1, new NistMirrorTask());
        jobEngine.registerWorker("update-metrics-portfolio", 1, new PortfolioMetricsUpdateTask());
        jobEngine.registerWorker("update-metrics-vulns", 1, new VulnerabilityMetricsUpdateTask());
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down engine manager");

        try {
            jobEngine.close();
        } catch (IOException | RuntimeException e) {
            LOGGER.warn("Graceful shutdown of job engine failed", e);
        }
    }

    private static class RandomlyFailingJobWorker implements JobWorker {

        private static final Logger LOGGER = Logger.getLogger(RandomlyFailingJobWorker.class);
        private final SecureRandom random;

        private RandomlyFailingJobWorker(final SecureRandom random) {
            this.random = random;
        }

        @Override
        public Optional<JobResult> process(final PolledJob job) throws Exception {
            LOGGER.debug("Processing " + job);

            Thread.sleep(random.nextInt(10, 1000));

            if (random.nextDouble() < 0.1) {
                if (random.nextDouble() > 0.3) {
                    throw new TransientJobException("I have the feeling this might resolve soon!");
                }

                throw new IllegalStateException("Oh no, this looks permanently broken!");
            }

            return Optional.empty();
        }

    }

}
