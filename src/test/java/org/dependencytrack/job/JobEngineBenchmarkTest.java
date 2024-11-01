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
import alpine.common.metrics.Metrics;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.search.MeterNotFoundException;
import org.dependencytrack.PersistenceCapableTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class JobEngineBenchmarkTest extends PersistenceCapableTest {

    private static final Logger LOGGER = Logger.getLogger(JobEngineBenchmarkTest.class);
    private static final int JOB_QUEUE_SIZE = 100_000;
    private static final int WORKER_CONCURRENCY = 10;

    private JobEngine jobEngine;
    private ScheduledExecutorService statPrinterExecutor;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        jobEngine = new JobEngine(Duration.ZERO, Duration.ofMillis(500));

        final var random = new SecureRandom();
        final var jobsToQueue = new ArrayList<NewJob>();
        for (int i = 0; i < JOB_QUEUE_SIZE; i++) {
            jobsToQueue.add(new NewJob(
                    "foo",
                    random.nextBoolean() ? random.nextInt(1, 100) : null,
                    null,
                    null,
                    null,
                    null,
                    null));
        }

        jobEngine.enqueueAll(jobsToQueue);
        jobEngine.start();

        useJdbiHandle(handle -> handle.createUpdate("ANALYZE \"JOB\"").execute());

        statPrinterExecutor = Executors.newSingleThreadScheduledExecutor();
        statPrinterExecutor.scheduleAtFixedRate(() -> {
            final Timer pollTimer, processTimer, flushTimer;
            try {
                pollTimer = Metrics.getRegistry().get("job_engine_poll").timer();
                processTimer = Metrics.getRegistry().get("job_worker_process").timer();
                flushTimer = Metrics.getRegistry().get("job_engine_event_flush").timer();
            } catch (MeterNotFoundException e) {
                LOGGER.info("Meters not ready yet");
                return;
            }

            LOGGER.info("""
                    Stats: \
                    poll={mean: %.2fms, max: %.2fms}, \
                    process={mean: %.2fms, max: %.2fms}, \
                    flush={mean: %.2fms, max: %.2fms}""".formatted(
                    pollTimer.mean(TimeUnit.MILLISECONDS),
                    pollTimer.max(TimeUnit.MILLISECONDS),
                    processTimer.mean(TimeUnit.MILLISECONDS),
                    processTimer.max(TimeUnit.MILLISECONDS),
                    flushTimer.mean(TimeUnit.MILLISECONDS),
                    flushTimer.max(TimeUnit.MILLISECONDS)));
        }, 0, 1, TimeUnit.SECONDS);
    }

    @After
    @Override
    public void after() {
        if (jobEngine != null) {
            assertThatNoException().isThrownBy(() -> jobEngine.close());
        }

        if (statPrinterExecutor != null) {
            statPrinterExecutor.shutdownNow();
            assertThatNoException().isThrownBy(
                    () -> statPrinterExecutor.awaitTermination(5, TimeUnit.SECONDS));
        }

        super.after();
    }

    @Test
    public void test() throws Exception {
        final var countDownLatch = new CountDownLatch(JOB_QUEUE_SIZE);

        jobEngine.registerWorker("foo", WORKER_CONCURRENCY, job -> {
            countDownLatch.countDown();
            return Optional.empty();
        });

        countDownLatch.await();

        await("Job completion")
                .untilAsserted(() -> {
                    final long completedJobs = withJdbiHandle(handle -> handle.createQuery(
                                    "SELECT COUNT(*) FROM \"JOB\" WHERE \"STATUS\" = 'COMPLETED'")
                            .mapTo(Long.class)
                            .one());
                    assertThat(completedJobs).isEqualTo(JOB_QUEUE_SIZE);
                });
    }

}