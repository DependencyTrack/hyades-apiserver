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
package org.dependencytrack.workflow.job;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.job.JobDao;
import org.dependencytrack.job.JobManager;
import org.dependencytrack.job.JobStatus;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.junit.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class JobManagerTest extends PersistenceCapableTest {

    @Test
    public void shouldMarkSuccessfulJobAsCompleted() throws Exception {
        try (final var jobManager = new JobManager()) {
            jobManager.enqueueAll(List.of(new NewJob("foo", null, null, null, null, null, null)));

            jobManager.registerWorker(Set.of("foo"), job -> Optional.empty(), 2);

            await("Job failure")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final List<QueuedJob> queuedJobs = withJdbiHandle(handle -> handle.attach(JobDao.class).getAllByTag("foo"));
                        assertThat(queuedJobs).satisfiesExactly(queuedJob -> assertThat(queuedJob.status()).isEqualTo(JobStatus.COMPLETED));
                    });
        }
    }

    @Test
    public void shouldMarkFailingJobAsFailed() throws Exception {
        try (final var jobManager = new JobManager()) {
            jobManager.enqueueAll(List.of(new NewJob("foo", null, null, null, null, null, null)));

            jobManager.registerWorker(Set.of("foo"), job -> {
                throw new IllegalStateException("Just for testing");
            }, 2);

            await("Job failure")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final List<QueuedJob> queuedJobs = withJdbiHandle(handle -> handle.attach(JobDao.class).getAllByTag("foo"));
                        assertThat(queuedJobs).satisfiesExactly(queuedJob -> assertThat(queuedJob.status()).isEqualTo(JobStatus.FAILED));
                    });
        }
    }

    @Test
    public void shouldPollJobsWithHigherPriorityFirst() throws Exception {
        try (final var jobManager = new JobManager()) {
            jobManager.enqueueAll(List.of(
                    new NewJob("foo", 5, null, null, null, null, null),
                    new NewJob("foo", 3, null, null, null, null, null),
                    new NewJob("foo", 4, null, null, null, null, null),
                    new NewJob("foo", 1, null, null, null, null, null),
                    new NewJob("foo", 2, null, null, null, null, null)));

            final var processedJobQueue = new ArrayBlockingQueue<QueuedJob>(5);
            jobManager.registerWorker(Set.of("foo"), job -> {
                processedJobQueue.add(job);
                return Optional.empty();
            }, 1);

            await("Job processing")
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