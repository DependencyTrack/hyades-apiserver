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
package org.dependencytrack.dex.engine;

import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.dex.api.failure.FailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.ExternalEvent;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.event.DexRunsCompletedEventListener;
import org.dependencytrack.dex.engine.api.pagination.Page;
import org.dependencytrack.dex.engine.api.request.CreateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.event.v1.Event;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;

@Testcontainers
class DexEngineImplTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();
    private static final String DEFAULT_WORKFLOW_TASK_QUEUE_NAME = "default";
    private static final String DEFAULT_ACTIVITY_TASK_QUEUE_NAME = "default";

    private DexEngineImpl engine;

    @BeforeEach
    void beforeEach() {
        postgresContainer.truncateTables();

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        dataSource.setDatabaseName(postgresContainer.getDatabaseName());

        final var config = new DexEngineConfig(UUID.randomUUID(), dataSource);

        engine = new DexEngineImpl(config);
        engine.createWorkflowTaskQueue(new CreateWorkflowTaskQueueRequest("default", 10));
        engine.createActivityTaskQueue(new CreateActivityTaskQueueRequest("default", 10));
    }

    @AfterEach
    void afterEach() {
        if (engine != null) {
            try {
                engine.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Test
    void shouldRunWorkflowWithArgumentAndResult() {
        engine.registerWorkflowInternal("test", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ctx.setStatus("someCustomStatus");
            return "someResult";
        });
        engine.registerWorkflowWorker(new  WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME)
                        .withConcurrencyGroupId("someConcurrencyGroupId")
                        .withPriority(6)
                        .withLabels(Map.of("label-a", "123", "label-b", "321"))
                        .withArgument("someArgument"));

        final WorkflowRunMetadata completedRun = awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(completedRun.customStatus()).isEqualTo("someCustomStatus");
        assertThat(completedRun.concurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
        assertThat(completedRun.priority()).isEqualTo(6);
        assertThat(completedRun.labels()).containsOnlyKeys("label-a", "label-b");
        assertThat(completedRun.createdAt()).isNotNull();
        assertThat(completedRun.updatedAt()).isNotNull();
        assertThat(completedRun.startedAt()).isNotNull();
        assertThat(completedRun.completedAt()).isNotNull();

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED);
                    assertThat(event.getRunCreated().getWorkflowName()).isEqualTo("test");
                    assertThat(event.getRunCreated().getWorkflowVersion()).isEqualTo(1);
                    assertThat(event.getRunCreated().getConcurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
                    assertThat(event.getRunCreated().getPriority()).isEqualTo(6);
                    assertThat(event.getRunCreated().getLabelsMap()).containsOnlyKeys("label-a", "label-b");
                    assertThat(event.getRunCreated().getArgument().hasBinaryContent()).isTrue();
                    assertThat(event.getRunCreated().getArgument().getBinaryContent().getData().toStringUtf8()).isEqualTo("someArgument");
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(0);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                    assertThat(event.getRunCompleted().getResult().hasBinaryContent()).isTrue();
                    assertThat(event.getRunCompleted().getResult().getBinaryContent().getData().toStringUtf8()).isEqualTo("someResult");
                    assertThat(event.getRunCompleted().hasFailure()).isFalse();
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED);
                });
    }

    @Test
    void shouldFailWorkflowRunWhenRunnerThrows() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            throw new IllegalStateException("Ouch!");
        });
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        final WorkflowRunMetadata failedRun = awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(failedRun.customStatus()).isNull();
        assertThat(failedRun.concurrencyGroupId()).isNull();
        assertThat(failedRun.priority()).isZero();
        assertThat(failedRun.labels()).isNull();
        assertThat(failedRun.createdAt()).isNotNull();
        assertThat(failedRun.updatedAt()).isNotNull();
        assertThat(failedRun.startedAt()).isNotNull();
        assertThat(failedRun.completedAt()).isNotNull();

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().hasResult()).isFalse();
                    assertThat(event.getRunCompleted().getFailure().getMessage()).isEqualTo("Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWorkflowRunOnNonDeterministicExecution() {
        final var executionCounter = new AtomicInteger(0);
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            if (executionCounter.incrementAndGet() == 1) {
                ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                        "abc", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, null, voidConverter(), stringConverter(), defaultRetryPolicy()).await();
            } else {
                ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                        "def", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, null, voidConverter(), stringConverter(), defaultRetryPolicy()).await();
            }
            return null;
        });
        engine.registerActivityInternal("abc", voidConverter(), voidConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> null);
        engine.registerActivityInternal("def", voidConverter(), voidConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> null);
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailure().getMessage()).startsWith("Detected non-deterministic workflow execution");
                },
                event -> assertThat(event.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWorkflowRunWhenCancelled() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.createTimer("sleep", Duration.ofSeconds(5)).await();
            return null;
        });
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        engine.requestRunCancellation(runId, "Stop it!");

        final WorkflowRunMetadata canceledRun = awaitRunStatus(runId, WorkflowRunStatus.CANCELED);

        assertThat(canceledRun.customStatus()).isNull();
        assertThat(canceledRun.concurrencyGroupId()).isNull();
        assertThat(canceledRun.priority()).isZero();
        assertThat(canceledRun.labels()).isNull();
        assertThat(canceledRun.createdAt()).isNotNull();
        assertThat(canceledRun.updatedAt()).isNotNull();
        assertThat(canceledRun.startedAt()).isNotNull();
        assertThat(canceledRun.completedAt()).isNotNull();

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CANCELED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_CANCELED);
                    assertThat(entry.getRunCompleted().hasResult()).isFalse();
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Stop it!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldWaitForTimerToElapse() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.createTimer("Sleep for 3 seconds", Duration.ofSeconds(5)).await();
            return null;
        });
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED);
                    assertThat(entry.getTimerCreated().getName()).isEqualTo("Sleep for 3 seconds");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldWaitForMultipleTimersToElapse() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            final var timers = new ArrayList<Awaitable<Void>>(3);
            for (int i = 0; i < 3; i++) {
                timers.add(ctx.createTimer("sleep" + i, Duration.ofSeconds(3)));
            }

            for (final Awaitable<Void> timer : timers) {
                timer.await();
            }

            return null;
        });
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId).withLimit(15)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldWaitForChildRun() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            final String childWorkflowResult = ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow(
                    "bar", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(childWorkflowResult).contains("inputValue-outputValue");
            return null;
        });

        engine.registerWorkflowInternal("bar", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5),
                (ctx, arg) -> arg + "-outputValue");

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.CHILD_RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.CHILD_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWhenChildRunFails() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow("bar", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            throw new IllegalStateException("Oh no!");
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.CHILD_RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.CHILD_RUN_FAILED);
                    assertThat(entry.getChildRunFailed().getFailure().getMessage()).isEqualTo("Oh no!");
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).matches("Run .+ of child workflow bar v1 failed");
                    assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Oh no!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCancelChildRunsRecursivelyWhenParentRunIsCancelled() {
        final var childRunIdReference = new AtomicReference<UUID>();
        final var grandChildRunIdReference = new AtomicReference<UUID>();

        engine.registerWorkflowInternal("parent", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow("child", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            childRunIdReference.set(ctx.runId());
            ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow("grand-child", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("grand-child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            grandChildRunIdReference.set(ctx.runId());
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 3));
        engine.start();

        final UUID parentRunId = engine.createRun(new CreateWorkflowRunRequest<>("parent", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        await("Grand Child Workflow Run Start")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(grandChildRunIdReference.get()).isNotNull());

        engine.requestRunCancellation(parentRunId, "someReason");

        awaitRunStatus(parentRunId, WorkflowRunStatus.CANCELED);
        awaitRunStatus(childRunIdReference.get(), WorkflowRunStatus.CANCELED);
        awaitRunStatus(grandChildRunIdReference.get(), WorkflowRunStatus.CANCELED);
    }

    @Test
    void shouldThrowWhenCancellingRunInTerminalState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> null);
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunCancellation(runId, "someReason"))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldSuspendAndResumeRunWhenRequested() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunResumption(runId);

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
    }

    @Test
    void shouldCancelSuspendedRunWhenRequested() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunCancellation(runId, "someReason");

        awaitRunStatus(runId, WorkflowRunStatus.CANCELED);
    }

    @Test
    void shouldThrowWhenSuspendingRunInTerminalState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> null);
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldThrowWhenSuspendingRunInSuspendedState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInNonSuspendedState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to act on the running run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ can not be resumed because it is not suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInTerminalState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> null);
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldWaitForExternalEvent() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunMetadata run = engine.getRunMetadata(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(new ExternalEvent(runId, "foo-123", null)).join();

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXTERNAL_EVENT_RECEIVED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWhenWaitingForExternalEventTimesOut() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofMillis(5)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_ELAPSED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Timed out while waiting for external event");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldRecordSideEffectResult() {
        final var sideEffectInvocationCounter = new AtomicInteger();

        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ctx.executeSideEffect("sideEffect", null, voidConverter(), ignored -> {
                sideEffectInvocationCounter.incrementAndGet();
                return null;
            }).await();

            ctx.createTimer("sleep", Duration.ofMillis(10)).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.SIDE_EFFECT_EXECUTED);
                    assertThat(entry.getSideEffectExecuted().getName()).isEqualTo("sideEffect");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldNotAllowNestedSideEffects() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ctx.executeSideEffect("outerSideEffect", null, voidConverter(), ignored -> {
                ctx.executeSideEffect("nestedSideEffect", null, voidConverter(), ignored2 -> null).await();
                return null;
            }).await();

            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().hasSideEffectFailureDetails()).isTrue();
                    assertThat(entry.getRunCompleted().getFailure().getCause().hasApplicationFailureDetails()).isTrue();
                    assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Nested side effects are not allowed");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCallActivity() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                    "abc", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, null, voidConverter(), stringConverter(), defaultRetryPolicy()).await();
            return null;
        });

        engine.registerActivityInternal("abc", voidConverter(), stringConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> "123");

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCreateMultipleActivitiesConcurrently() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            final List<Awaitable<String>> awaitables = List.of(
                    ((WorkflowContextImpl<?, ?>) ctx).callActivity("abc", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, "first", stringConverter(), stringConverter(), defaultRetryPolicy()),
                    ((WorkflowContextImpl<?, ?>) ctx).callActivity("abc", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, "second", stringConverter(), stringConverter(), defaultRetryPolicy()));

            return awaitables.stream()
                    .map(Awaitable::await)
                    .collect(Collectors.joining(", "));
        });

        engine.registerActivityInternal("abc", stringConverter(), stringConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> arg);

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, 2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId).withLimit(15)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldRetryFailingActivity() {
        final var retryPolicy = defaultRetryPolicy()
                .withMaxDelay(Duration.ofMillis(10))
                .withMaxAttempts(3);

        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                    "abc", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, null, voidConverter(), stringConverter(), retryPolicy).await();
            return null;
        });

        engine.registerActivityInternal("abc", voidConverter(), stringConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> {
            throw new IllegalStateException();
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId).withLimit(20)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldNotRetryActivityFailingWithTerminalException() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                    "abc", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, null, voidConverter(), stringConverter(), defaultRetryPolicy()).await();
            return null;
        });

        engine.registerActivityInternal("abc", voidConverter(), stringConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> {
            throw new TerminalApplicationFailureException("Ouch!", null);
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.ACTIVITY_TASK_FAILED);
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldPropagateExceptions() {
        final AtomicReference<FailureException> exceptionReference = new AtomicReference<>();

        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            try {
                ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow("bar", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, null, voidConverter(), voidConverter()).await();
            } catch (FailureException e) {
                exceptionReference.set(e);
                throw e;
            }

            return null;
        });

        engine.registerWorkflowInternal("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow("baz", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("baz", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity("qux", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, null, voidConverter(), voidConverter(), defaultRetryPolicy()).await();
            return null;
        });

        engine.registerActivityInternal("qux", voidConverter(), voidConverter(), Duration.ofSeconds(5), false, (ctx, arg) -> {
            throw new TerminalApplicationFailureException("Ouch!", null);
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 3));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", DEFAULT_ACTIVITY_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME)
                .withLabels(Map.of("oof", "rab")));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED, Duration.ofSeconds(15));

        assertThat(exceptionReference.get()).satisfies(e -> {
            assertThat(e).isInstanceOf(ChildWorkflowFailureException.class);
            assertThat(e.getMessage()).matches("Run .+ of child workflow bar v1 failed");
            assertThat(e.getStackTrace()).isNotEmpty();

            {
                final var failure = (ChildWorkflowFailureException) e;
                assertThat(failure.getRunId()).isNotNull();
                assertThat(failure.getWorkflowName()).isEqualTo("bar");
                assertThat(failure.getWorkflowVersion()).isEqualTo(1);
            }

            assertThat(e.getCause()).satisfies(firstCause -> {
                assertThat(firstCause).isInstanceOf(ChildWorkflowFailureException.class);
                assertThat(firstCause.getMessage()).matches("Run .+ of child workflow baz v1 failed");
                assertThat(firstCause.getStackTrace()).isNotEmpty();

                {
                    final var failure = (ChildWorkflowFailureException) firstCause;
                    assertThat(failure.getRunId()).isNotNull();
                    assertThat(failure.getWorkflowName()).isEqualTo("baz");
                    assertThat(failure.getWorkflowVersion()).isEqualTo(1);
                }

                assertThat(firstCause.getCause()).satisfies(secondCause -> {
                    assertThat(secondCause).isInstanceOf(ActivityFailureException.class);
                    assertThat(secondCause.getMessage()).isEqualTo("Activity qux failed");
                    assertThat(secondCause.getStackTrace()).isNotEmpty();

                    {
                        final var failure = (ActivityFailureException) secondCause;
                        assertThat(failure.getActivityName()).isEqualTo("qux");
                    }

                    assertThat(secondCause.getCause()).satisfies(thirdCause -> {
                        assertThat(thirdCause).isInstanceOf(ApplicationFailureException.class);
                        assertThat(thirdCause.getMessage()).isEqualTo("Ouch!");
                        assertThat(thirdCause.getStackTrace()).isNotEmpty();
                        assertThat(thirdCause.getCause()).isNull();

                        {
                            final var failure = (ApplicationFailureException) thirdCause;
                            assertThat(failure.isTerminal()).isTrue();
                        }
                    });
                });
            });
        });
    }

    @Test
    void shouldPropagateLabels() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            ((WorkflowContextImpl<?, ?>) ctx).callChildWorkflow("bar", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 2));
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME)
                        .withLabels(Map.of("oof", "123", "rab", "321")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED);
                    assertThat(entry.getRunCreated().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.CHILD_RUN_CREATED);
                    assertThat(entry.getChildRunCreated().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.CHILD_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldContinueAsNew() {
        engine.registerWorkflowInternal("foo", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            final int iteration = Integer.parseInt(arg);
            ctx.executeSideEffect("abc-" + iteration, null, stringConverter(), ignored -> "def-" + iteration).await();
            if (iteration < 3) {
                ctx.continueAsNew(
                        new ContinueAsNewOptions<String>()
                                .withArgument(String.valueOf(iteration + 1)));
            }
            return String.valueOf(iteration);
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME)
                        .withArgument("0"));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED), // TODO: Get rid of this.
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_CREATED);
                    assertThat(stringConverter().convertFromPayload(entry.getRunCreated().getArgument())).isEqualTo("3");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.SIDE_EFFECT_EXECUTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.RUN_COMPLETED);
                    assertThat(stringConverter().convertFromPayload(entry.getRunCompleted().getResult())).isEqualTo("3");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(Event.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldInformEventListenersAboutCompletedRuns() {
        final var completedRuns = new ArrayList<WorkflowRunMetadata>();
        engine.addEventListener((DexRunsCompletedEventListener) event -> {
            completedRuns.addAll(event.completedRuns());
        });

        engine.registerWorkflowInternal("foo", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            final boolean shouldFail = Boolean.parseBoolean(arg);
            if (shouldFail) {
                throw new IllegalStateException();
            }

            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID succeedingRunId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME).withArgument("false"));
        final UUID failingRunId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME).withArgument("true"));

        awaitRunStatus(succeedingRunId, WorkflowRunStatus.COMPLETED);
        awaitRunStatus(failingRunId, WorkflowRunStatus.FAILED);

        await("Run completion events")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(completedRuns).hasSize(2));

        assertThat(completedRuns).satisfiesExactlyInAnyOrder(
                run -> {
                    assertThat(run.id()).isEqualTo(succeedingRunId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                },
                run -> {
                    assertThat(run.id()).isEqualTo(failingRunId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });
    }

    @Test
    void shouldSupportWorkflowVersioning() {
        // TODO
    }

    @Test
    void shouldListRuns() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> null);

        for (int i = 0; i < 10; i++) {
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));
        }

        Page<WorkflowRunMetadata> runsPage = engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLimit(5));
        assertThat(runsPage.items()).hasSize(5);
        assertThat(runsPage.nextPageToken()).isNotNull();

        runsPage = engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withPageToken(runsPage.nextPageToken())
                        .withLimit(5));
        assertThat(runsPage.items()).hasSize(5);
        assertThat(runsPage.nextPageToken()).isNull();
    }

    @Test
    void shouldListRunEvents() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), (ctx, arg) -> {
            ctx.executeSideEffect("a", null, voidConverter(), ignored -> null).await();
            ctx.executeSideEffect("b", null, voidConverter(), ignored -> null).await();
            return null;
        });

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", DEFAULT_WORKFLOW_TASK_QUEUE_NAME, 1));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, DEFAULT_WORKFLOW_TASK_QUEUE_NAME));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        Page<Event> historyPage = engine.listRunEvents(
                new ListWorkflowRunEventsRequest(runId)
                        .withLimit(3));
        assertThat(historyPage.items()).satisfiesExactly(
                event -> assertThat(event.hasExecutionStarted()).isTrue(),
                event -> assertThat(event.hasRunCreated()).isTrue(),
                event -> assertThat(event.hasRunStarted()).isTrue());
        assertThat(historyPage.nextPageToken()).isNotNull();

        historyPage = engine.listRunEvents(
                new ListWorkflowRunEventsRequest(runId)
                        .withPageToken(historyPage.nextPageToken())
                        .withLimit(2));
        assertThat(historyPage.items()).satisfiesExactly(
                event -> assertThat(event.hasSideEffectExecuted()).isTrue(),
                event -> assertThat(event.hasSideEffectExecuted()).isTrue());
        assertThat(historyPage.nextPageToken()).isNotNull();
    }

    private WorkflowRunMetadata awaitRunStatus(
            final UUID runId,
            final WorkflowRunStatus expectedStatus,
            final Duration timeout) {
        return await("Workflow Run Status to become " + expectedStatus)
                .atMost(timeout)
                .failFast(() -> {
                    final WorkflowRunStatus currentStatus = engine.getRunMetadata(runId).status();
                    if (currentStatus.isTerminal() && !expectedStatus.isTerminal()) {
                        return true;
                    }

                    return currentStatus.isTerminal()
                            && expectedStatus.isTerminal()
                            && currentStatus != expectedStatus;
                })
                .until(() -> engine.getRunMetadata(runId), run -> run.status() == expectedStatus);
    }

    private WorkflowRunMetadata awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(5));
    }

}