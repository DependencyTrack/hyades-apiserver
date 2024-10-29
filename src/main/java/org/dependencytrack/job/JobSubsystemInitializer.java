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

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.Set;

public class JobSubsystemInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(JobSubsystemInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing job manager");
        final var jobManager = JobManager.getInstance();
        jobManager.registerWorker(Set.of("consume-bom"), new RandomlyFailingJobWorker(), 2);
        jobManager.registerWorker(Set.of("process-bom"), new RandomlyFailingJobWorker(), 1);
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Shutting down job manager");

        try {
            JobManager.getInstance().close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class RandomlyFailingJobWorker implements JobWorker {

        private static final Logger LOGGER = Logger.getLogger(RandomlyFailingJobWorker.class);
        private final SecureRandom random = new SecureRandom();

        @Override
        public Optional<JobResult> process(final QueuedJob job) {
            LOGGER.info("Processing: " + job);

            if (random.nextBoolean()) {
                throw new IllegalStateException("Oh no!");
            }

            return Optional.empty();
        }

    }

}
