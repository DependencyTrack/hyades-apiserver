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

import alpine.common.logging.Logger;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.job.JobDao;
import org.dependencytrack.job.JobManager;
import org.dependencytrack.job.JobStatus;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.junit.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class JobManagerTest extends PersistenceCapableTest {

    @Test
    public void foo() throws Exception {
        useJdbiTransaction(handle -> handle.attach(JobDao.class).enqueue(
                new NewJob("foo", null, Instant.now().plusSeconds(15), null, null, null, null)));

        final Logger logger = Logger.getLogger(getClass());
        try (final var jobManager = new JobManager()) {
            jobManager.registerWorker(Set.of("foo"), job -> {
                throw new IllegalStateException();
            }, 2);

            await("Job completion")
                    .atMost(30, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final List<QueuedJob> queuedJobs = withJdbiHandle(handle -> handle.attach(JobDao.class).getAllByTag("foo"));
                        assertThat(queuedJobs).satisfiesExactly(queuedJob -> assertThat(queuedJob.status()).isEqualTo(JobStatus.FAILED));
                    });
        }
    }

    @Test
    public void test() {
        useJdbiTransaction(jdbiHandle -> {
            final var dao = jdbiHandle.attach(JobDao.class);

            final var newJob = new NewJob("foo", 666, Instant.now(), null, null, null, null);

            final QueuedJob queuedJob = dao.enqueue(newJob);
            assertThat(queuedJob).isNotNull();

            final QueuedJob polledJob = dao.poll(Set.of("foo"));
            assertThat(polledJob).isNotNull();
            assertThat(polledJob.id()).isGreaterThan(0);
            assertThat(polledJob.status()).isEqualTo(JobStatus.RUNNING);
            assertThat(polledJob.priority()).isEqualTo(666);
            assertThat(polledJob.createdAt()).isNotNull();
            assertThat(polledJob.startedAt()).isNotNull();
            assertThat(polledJob.attempts()).isEqualTo(1);

            final QueuedJob secondPolledJob = dao.poll(Set.of("foo"));
            assertThat(secondPolledJob).isNull();
        });

    }

}