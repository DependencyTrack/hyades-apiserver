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

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.job.persistence.PolledJob;
import org.dependencytrack.job.persistence.QueuedJobRowMapper;
import org.dependencytrack.proto.job.v1alpha1.JobArgs;
import org.dependencytrack.proto.job.v1alpha1.UpdateProjectMetricsJobArgs;
import org.dependencytrack.proto.workflow.v1alpha1.ProcessBomUploadWorkflowRunArgs;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunArgs;
import org.dependencytrack.workflow.StartWorkflowOptions;
import org.dependencytrack.workflow.WorkflowEngine;
import org.dependencytrack.workflow.WorkflowRunView;
import org.dependencytrack.workflow.WorkflowSpec;
import org.dependencytrack.workflow.WorkflowStepSpec;
import org.dependencytrack.workflow.WorkflowStepType;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.proto.job.v1alpha1.JobArgs.ArgsCase.UPDATE_PROJECT_METRICS_ARGS;

public class JobEngineTest extends PersistenceCapableTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.8.0");

    private AdminClient adminClient;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        environmentVariables.set("KAFKA_BOOTSTRAP_SERVERS", kafkaContainer.getBootstrapServers());

        adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()));
        adminClient.createTopics(List.of(new NewTopic("dtrack.event.job", 3, (short) 1))).all().get();
    }

    @After
    @Override
    public void after() {
        if (adminClient != null) {
            assertThatNoException().isThrownBy(
                    () -> adminClient.deleteTopics(List.of("dtrack.event.job")).all().get());
            adminClient.close();
        }

        super.after();
    }

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
        try (final var jobEngine = new JobEngine()) {
            jobEngine.start();

            final QueuedJob queuedJob = jobEngine.enqueue(new NewJob("foo"));

            jobEngine.registerWorker("foo", 2, job -> Optional.empty());

            await("Job completion")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final QueuedJob completedJob = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT * FROM \"JOB\" WHERE \"ID\" = :id")
                                .bind("id", queuedJob.id())
                                .map(new QueuedJobRowMapper())
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
        try (final var jobEngine = new JobEngine()) {
            jobEngine.start();

            final QueuedJob queuedJob = jobEngine.enqueue(new NewJob("foo"));

            jobEngine.registerWorker("foo", 2, job -> {
                throw new IllegalStateException("Just for testing");
            });

            await("Job failure")
                    .atMost(5, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final QueuedJob completedJob = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT * FROM \"JOB\" WHERE \"ID\" = :id")
                                .bind("id", queuedJob.id())
                                .map(new QueuedJobRowMapper())
                                .one());
                        assertThat(completedJob.status()).isEqualTo(JobStatus.FAILED);
                        assertThat(completedJob.updatedAt()).isNotNull();
                        assertThat(completedJob.attempts()).isEqualTo(1);
                        assertThat(completedJob.failureReason()).isEqualTo("Just for testing");
                    });
        }
    }

    @Test
    public void shouldRetryFailingJobsWithTransientCause() throws Exception {
        try (final var jobEngine = new JobEngine()) {
            jobEngine.start();

            final QueuedJob queuedJob = jobEngine.enqueue(new NewJob("foo"));

            final var attempts = new AtomicInteger(0);
            jobEngine.registerWorker("foo", 1, job -> {
                if (attempts.incrementAndGet() == 3) {
                    return Optional.empty();
                }

                throw new TransientJobException("Attempt %s failed".formatted(attempts.get()));
            });

            await("Job failure")
                    .atMost(30, TimeUnit.SECONDS)
                    .untilAsserted(() -> {
                        final QueuedJob completedJob = withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT * FROM \"JOB\" WHERE \"ID\" = :id")
                                .bind("id", queuedJob.id())
                                .map(new QueuedJobRowMapper())
                                .one());
                        assertThat(completedJob.status()).isEqualTo(JobStatus.COMPLETED);
                        assertThat(completedJob.updatedAt()).isNotNull();
                        assertThat(completedJob.attempts()).isEqualTo(3);
                        assertThat(completedJob.failureReason()).isNull();
                    });
        }
    }

    @Test
    public void shouldPollJobsWithHigherPriorityFirst() throws Exception {
        try (final var jobEngine = new JobEngine()) {
            jobEngine.start();

            jobEngine.enqueueAll(List.of(
                    new NewJob("foo").withPriority(5),
                    new NewJob("foo").withPriority(3),
                    new NewJob("foo").withPriority(4),
                    new NewJob("foo").withPriority(1),
                    new NewJob("foo").withPriority(2)));

            final var processedJobQueue = new ArrayBlockingQueue<PolledJob>(5);
            jobEngine.registerWorker("foo", 1, job -> {
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

    @Test
    public void shouldPollJobsWithWorkflowArguments() throws Exception {
        final var workflowRunArgs = WorkflowRunArgs.newBuilder()
                .setProcessBomUploadArgs(ProcessBomUploadWorkflowRunArgs.newBuilder()
                        .setProjectUuid("426af683-277c-405d-8b9c-4b05c3838534")
                        .setProjectName("acme-app")
                        .setProjectVersion("1.0.0")
                        .build())
                .build();

        final WorkflowRunView workflowRun;
        final var polledJobQueue = new ArrayBlockingQueue<PolledJob>(1);
        try (final var jobEngine = new JobEngine();
             final var workflowEngine = new WorkflowEngine(jobEngine)) {
            jobEngine.start();
            jobEngine.registerWorker("bar", 1, job -> {
                polledJobQueue.add(job);
                return Optional.empty();
            });

            workflowEngine.start();
            workflowEngine.deploy(new WorkflowSpec(
                    "foo", 1, List.of(new WorkflowStepSpec("bar", WorkflowStepType.JOB, Collections.emptySet()))));
            workflowRun = workflowEngine.startWorkflow(
                    new StartWorkflowOptions("foo", 1)
                            .withPriority(666)
                            .withArguments(workflowRunArgs));

            await("Job polling")
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(polledJobQueue).hasSize(1));
        }

        assertThat(polledJobQueue).satisfiesExactly(job -> {
            assertThat(job.id()).isPositive();
            assertThat(job.status()).isEqualTo(JobStatus.RUNNING);
            assertThat(job.kind()).isEqualTo("bar");
            assertThat(job.priority()).isEqualTo(666);
            assertThat(job.scheduledFor()).isBeforeOrEqualTo(Instant.now());
            assertThat(job.workflowRunId()).isPositive();
            assertThat(job.workflowRunToken()).isEqualTo(workflowRun.token());
            assertThat(job.workflowRunArgs()).isEqualTo(workflowRunArgs);
            assertThat(job.createdAt()).isBeforeOrEqualTo(Instant.now());
            assertThat(job.updatedAt()).isBeforeOrEqualTo(Instant.now());
            assertThat(job.startedAt()).isBeforeOrEqualTo(Instant.now());
            assertThat(job.attempt()).isEqualTo(1);
        });
    }

    @Test
    public void shouldPersistJobArguments() throws Exception {
        try (final var jobEngine = new JobEngine()) {
            jobEngine.start();

            final QueuedJob queuedJob = jobEngine.enqueue(new NewJob("foo")
                    .withArguments(JobArgs.newBuilder()
                            .setUpdateProjectMetricsArgs(UpdateProjectMetricsJobArgs.newBuilder()
                                    .setProjectUuid("5423bf42-cdce-4248-ada7-b03da317cdf4")
                                    .build())
                            .build()));

            assertThat(queuedJob.arguments().getArgsCase()).isEqualTo(UPDATE_PROJECT_METRICS_ARGS);
            assertThat(queuedJob.arguments().getUpdateProjectMetricsArgs().getProjectUuid()).isEqualTo("5423bf42-cdce-4248-ada7-b03da317cdf4");
        }
    }

}