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

import org.dependencytrack.PersistenceCapableTest;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.junit.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class JobEngineTest extends PersistenceCapableTest {

    @Test
    public void shouldHaveInitialStateCreated() throws Exception {
        final var jobEngine = new JobEngine();
        assertThat(jobEngine.state()).isEqualTo(JobEngine.State.CREATED);

        jobEngine.close(); // Should be no-op.
        assertThat(jobEngine.state()).isEqualTo(JobEngine.State.CREATED);
    }

    @Test
    public void shouldHaveStatusStoppedAfterClose() throws Exception {
        final var jobEngine = new JobEngine();
        try (jobEngine) {
            jobEngine.start();
            assertThat(jobEngine.state()).isEqualTo(JobEngine.State.RUNNING);
        }

        assertThat(jobEngine.state()).isEqualTo(JobEngine.State.STOPPED);
    }

    @Test
    public void shouldMarkSuccessfulJobAsCompleted() throws Exception {
        try (final var jobEngine = new JobEngine(10, Duration.ZERO, Duration.ofMillis(100))) {
            jobEngine.start();

            final QueuedJob queuedJob = jobEngine.enqueue(new NewJob("foo", null, null, null, null, null, null));

            jobEngine.registerWorker(Set.of("foo"), 2, job -> Optional.empty());

            await("Job completion")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final QueuedJob completedJob = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT * FROM \"JOB\" WHERE \"ID\" = :id")
                                .bind("id", queuedJob.id())
                                .map(ConstructorMapper.of(QueuedJob.class))
                                .one());
                        assertThat(completedJob.status()).isEqualTo(JobStatus.COMPLETED);
                        assertThat(completedJob.updatedAt()).isNotNull();
                        assertThat(completedJob.attempts()).isEqualTo(1);
                        assertThat(completedJob.failureReason()).isNull();
                    });
        }
    }

    @Test
    public void shouldMarkFailingJobAsFailed() throws Exception {
        try (final var jobEngine = new JobEngine(10, Duration.ZERO, Duration.ofMillis(100))) {
            jobEngine.start();

            final QueuedJob queuedJob = jobEngine.enqueue(new NewJob("foo", null, null, null, null, null, null));

            jobEngine.registerWorker(Set.of("foo"), 2, job -> {
                throw new IllegalStateException("Just for testing");
            });

            await("Job failure")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final QueuedJob completedJob = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT * FROM \"JOB\" WHERE \"ID\" = :id")
                                .bind("id", queuedJob.id())
                                .map(ConstructorMapper.of(QueuedJob.class))
                                .one());
                        assertThat(completedJob.status()).isEqualTo(JobStatus.FAILED);
                        assertThat(completedJob.updatedAt()).isNotNull();
                        assertThat(completedJob.attempts()).isEqualTo(1);
                        assertThat(completedJob.failureReason()).isEqualTo("Just for testing");
                    });
        }
    }

    @Test
    public void shouldPollJobsWithHigherPriorityFirst() throws Exception {
        try (final var jobEngine = new JobEngine(10, Duration.ZERO, Duration.ofMillis(100))) {
            jobEngine.start();

            jobEngine.enqueueAll(List.of(
                    new NewJob("foo", 5, null, null, null, null, null),
                    new NewJob("foo", 3, null, null, null, null, null),
                    new NewJob("foo", 4, null, null, null, null, null),
                    new NewJob("foo", 1, null, null, null, null, null),
                    new NewJob("foo", 2, null, null, null, null, null)));

            final var processedJobQueue = new ArrayBlockingQueue<QueuedJob>(5);
            jobEngine.registerWorker(Set.of("foo"), 1, job -> {
                processedJobQueue.add(job);
                return Optional.empty();
            });

            await("Job completion")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> assertThat(processedJobQueue).hasSize(5));

            assertThat(processedJobQueue).satisfiesExactly(
                    job -> assertThat(job.priority()).isEqualTo(5),
                    job -> assertThat(job.priority()).isEqualTo(4),
                    job -> assertThat(job.priority()).isEqualTo(3),
                    job -> assertThat(job.priority()).isEqualTo(2),
                    job -> assertThat(job.priority()).isEqualTo(1));
        }
    }

}