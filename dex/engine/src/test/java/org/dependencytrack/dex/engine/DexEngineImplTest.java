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

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.api.ActivityExecutor;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowExecutor;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.dex.api.failure.FailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.ExternalEvent;
import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.TaskQueueStatus;
import org.dependencytrack.dex.engine.api.TaskQueueType;
import org.dependencytrack.dex.engine.api.WorkflowRunConcurrencyMode;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;

@Testcontainers
class DexEngineImplTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();
    private static final String WORKFLOW_TASK_QUEUE = "default";
    private static final String ACTIVITY_TASK_QUEUE = "default";

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
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, WORKFLOW_TASK_QUEUE, 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, ACTIVITY_TASK_QUEUE, 10));
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
        registerWorkflow("test", stringConverter(), stringConverter(), (ctx, arg) -> {
            ctx.setStatus("someCustomStatus");
            return "someResult";
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE)
                        .withConcurrency("someConcurrencyGroupId", WorkflowRunConcurrencyMode.SERIAL)
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

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED);
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

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(0);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                    assertThat(event.getRunCompleted().getResult().hasBinaryContent()).isTrue();
                    assertThat(event.getRunCompleted().getResult().getBinaryContent().getData().toStringUtf8()).isEqualTo("someResult");
                    assertThat(event.getRunCompleted().hasFailure()).isFalse();
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED);
                });
    }

    @Test
    void shouldFailWorkflowRunWhenRunnerThrows() {
        registerWorkflow("test", (ctx, arg) -> {
            throw new IllegalStateException("Ouch!");
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

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
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().hasResult()).isFalse();
                    assertThat(event.getRunCompleted().getFailure().getMessage()).isEqualTo("Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWorkflowRunOnNonDeterministicExecution() {
        final var executionCounter = new AtomicInteger(0);

        registerWorkflow("test", (ctx, arg) -> {
            if (executionCounter.incrementAndGet() == 1) {
                ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            } else {
                ctx.callActivity("def", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            }
            return null;
        });
        registerActivity("abc", (ctx, arg) -> null);
        registerActivity("def", (ctx, arg) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 1);

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailure().getMessage()).startsWith("Detected non-deterministic workflow execution");
                },
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWorkflowRunWhenCancelled() {
        registerWorkflow("test", (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.createTimer("sleep", Duration.ofSeconds(5)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

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
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CANCELED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_CANCELED);
                    assertThat(entry.getRunCompleted().hasResult()).isFalse();
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Stop it!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldWaitForTimerToElapse() {
        registerWorkflow("test", (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.createTimer("Sleep for 3 seconds", Duration.ofSeconds(5)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED);
                    assertThat(entry.getTimerCreated().getName()).isEqualTo("Sleep for 3 seconds");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldWaitForMultipleTimersToElapse() {
        registerWorkflow("test", (ctx, arg) -> {
            final var timers = new ArrayList<Awaitable<Void>>(3);
            for (int i = 0; i < 3; i++) {
                timers.add(ctx.createTimer("sleep" + i, Duration.ofSeconds(3)));
            }

            for (final Awaitable<Void> timer : timers) {
                timer.await();
            }

            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId).withLimit(15)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldWaitForChildRun() {
        registerWorkflow("foo", (ctx, arg) -> {
            final String childWorkflowResult =
                    ctx.callChildWorkflow("bar", 1, WORKFLOW_TASK_QUEUE, null, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(childWorkflowResult).contains("inputValue-outputValue");
            return null;
        });
        registerWorkflow("bar", stringConverter(), stringConverter(), (ctx, arg) -> arg + "-outputValue");
        registerWorkflowWorker("workflow-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWhenChildRunFails() {
        registerWorkflow("foo", (ctx, arg) -> {
            ctx.callChildWorkflow("bar", 1, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("bar", (ctx, arg) -> {
            throw new IllegalStateException("Oh no!");
        });
        registerWorkflowWorker("workflow-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_FAILED);
                    assertThat(entry.getChildRunFailed().getFailure().getMessage()).isEqualTo("Oh no!");
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).matches("Run .+ of child workflow bar v1 failed");
                    assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Oh no!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCancelChildRunsRecursivelyWhenParentRunIsCancelled() {
        final var childRunIdReference = new AtomicReference<UUID>();
        final var grandChildRunIdReference = new AtomicReference<UUID>();

        registerWorkflow("parent", (ctx, arg) -> {
            ctx.callChildWorkflow("child", 1, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("child", (ctx, arg) -> {
            childRunIdReference.set(ctx.runId());
            ctx.callChildWorkflow("grand-child", 1, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("grand-child", (ctx, arg) -> {
            grandChildRunIdReference.set(ctx.runId());
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 3);
        engine.start();

        final UUID parentRunId = engine.createRun(new CreateWorkflowRunRequest<>("parent", 1, WORKFLOW_TASK_QUEUE));

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
        registerWorkflow("test", (ctx, arg) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunCancellation(runId, "someReason"))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldSuspendAndResumeRunWhenRequested() {
        registerWorkflow("test", (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunResumption(runId);

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
    }

    @Test
    void shouldCancelSuspendedRunWhenRequested() {
        registerWorkflow("test", (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunCancellation(runId, "someReason");

        awaitRunStatus(runId, WorkflowRunStatus.CANCELED);
    }

    @Test
    void shouldThrowWhenSuspendingRunInTerminalState() {
        registerWorkflow("test", (ctx, arg) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldThrowWhenSuspendingRunInSuspendedState() {
        registerWorkflow("test", (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInNonSuspendedState() {
        registerWorkflow("test", (ctx, arg) -> {
            // Sleep for a moment so we get an opportunity to act on the running run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ can not be resumed because it is not suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInTerminalState() {
        registerWorkflow("test", (ctx, arg) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Nested
    class ConcurrencyGroupTest {

        @Test
        void shouldNotCreateRunWhenConcurrencyModeIsExclusiveAndAnotherRunIsInProgress() {
            registerWorkflow("test", stringConverter(), voidConverter(), (ctx, arg) -> null);

            UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE)
                            .withConcurrency("concurrencyGroup", WorkflowRunConcurrencyMode.EXCLUSIVE));
            assertThat(runId).isNotNull();

            runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE)
                            .withConcurrency("concurrencyGroup", WorkflowRunConcurrencyMode.EXCLUSIVE));
            assertThat(runId).isNull();
        }

        @Test
        void shouldExecuteRunsWithSameConcurrencyGroupInPriorityOrder() {
            final var executionQueue = new ArrayBlockingQueue<String>(5);

            registerWorkflow("test", stringConverter(), voidConverter(), (ctx, arg) -> {
                executionQueue.add(arg);
                return null;
            });
            registerWorkflowWorker("workflow-worker", 5);
            engine.start();

            final var concurrencyGroupId = "concurrencyGroup";

            final List<CreateWorkflowRunResponse> responses = engine.createRuns(
                    Stream.of(1, 2, 3, 4, 5)
                            .<CreateWorkflowRunRequest<?>>map(
                                    number -> new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE)
                                            .withConcurrency(concurrencyGroupId, WorkflowRunConcurrencyMode.SERIAL)
                                            .withPriority(number)
                                            .withArgument(String.valueOf(number)))
                            .toList());

            for (final var response : responses) {
                awaitRunStatus(response.runId(), WorkflowRunStatus.COMPLETED, Duration.ofSeconds(5));
            }

            assertThat(executionQueue).containsExactly("5", "4", "3", "2", "1");
        }

    }

    @Test
    void shouldWaitForExternalEvent() {
        registerWorkflow("test", (ctx, arg) -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunMetadata run = engine.getRunMetadata(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(new ExternalEvent(runId, "foo-123", null)).join();

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXTERNAL_EVENT_RECEIVED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWhenWaitingForExternalEventTimesOut() {
        registerWorkflow("test", (ctx, arg) -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofMillis(5)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Timed out while waiting for external event");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Nested
    class SideEffectTest {

        @Test
        void shouldRecordSideEffectResult() {
            final var sideEffectInvocationCounter = new AtomicInteger();

            registerWorkflow("test", (ctx, arg) -> {
                ctx.executeSideEffect("sideEffect", sideEffectInvocationCounter::incrementAndGet).await();

                ctx.createTimer("sleep", Duration.ofMillis(10)).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

            assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED);
                        assertThat(entry.getSideEffectExecuted().getName()).isEqualTo("sideEffect");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
        }

        @Test
        void shouldNotAllowNestedSideEffects() {
            registerWorkflow("test", (ctx, arg) -> {
                ctx.executeSideEffect("outerSideEffect", () -> ctx.executeSideEffect("nestedSideEffect", () -> {
                }).await()).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

            awaitRunStatus(runId, WorkflowRunStatus.FAILED);

            assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                        assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(entry.getRunCompleted().getFailure().hasSideEffectFailureDetails()).isTrue();
                        assertThat(entry.getRunCompleted().getFailure().getCause().hasApplicationFailureDetails()).isTrue();
                        assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Nested side effects are not allowed");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
        }

    }

    @Test
    void shouldCallActivity() {
        registerWorkflow("test", (ctx, arg) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("abc", voidConverter(), stringConverter(), (ctx, arg) -> "123");
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCreateMultipleActivitiesConcurrently() {
        registerWorkflow("test", voidConverter(), stringConverter(), (ctx, arg) -> {
            final List<Awaitable<String>> awaitables = List.of(
                    ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, "first", stringConverter(), stringConverter(), RetryPolicy.ofDefault()),
                    ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, "second", stringConverter(), stringConverter(), RetryPolicy.ofDefault()));

            return awaitables.stream()
                    .map(Awaitable::await)
                    .collect(Collectors.joining(", "));
        });
        registerActivity("abc", stringConverter(), stringConverter(), (ctx, arg) -> arg);
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId).withLimit(15)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldRetryFailingActivity() {
        final var retryPolicy = RetryPolicy.ofDefault()
                .withMaxDelay(Duration.ofMillis(10))
                .withMaxAttempts(3);

        registerWorkflow("test", (ctx, arg) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), retryPolicy).await();
            return null;
        });
        registerActivity("abc", voidConverter(), stringConverter(), (ctx, arg) -> {
            throw new IllegalStateException();
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId).withLimit(20)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED);
                    assertThat(entry.getActivityTaskFailed().getAttempts()).isEqualTo(3);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldNotRetryActivityFailingWithTerminalException() {
        registerWorkflow("test", (ctx, arg) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("abc", voidConverter(), stringConverter(), (ctx, arg) -> {
            throw new TerminalApplicationFailureException("Ouch!", null);
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED);
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldHeartbeatActivity() {
        final var heartbeatsPerformed = new ArrayBlockingQueue<Boolean>(3);

        registerWorkflow("test", (ctx, arg) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("test", (ctx, arg) -> {
            heartbeatsPerformed.add(ctx.maybeHeartbeat());
            Thread.sleep(3_500);
            heartbeatsPerformed.add(ctx.maybeHeartbeat());
            heartbeatsPerformed.add(ctx.maybeHeartbeat());
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));
        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(heartbeatsPerformed).containsExactly(false, true, false);
    }

    @Test
    void shouldCancelActivitiesDuringGracefulShutdown() throws Exception {
        final var activityStarted = new AtomicBoolean(false);
        final var activityCanceled = new AtomicBoolean(false);

        registerWorkflow("test", (ctx, arg) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("test", (ctx, arg) -> {
            while (true) {
                activityStarted.set(true);
                if (ctx.isCanceled()) {
                    // NB: Normally activities should throw an exception
                    // so they'll be retried. This is just for ease of testing.
                    activityCanceled.set(true);
                    return null;
                }
                Thread.sleep(5);
            }
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerActivityWorker("activity-worker", 1);
        engine.start();

        engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));

        await("Activity start")
                .atMost(Duration.ofSeconds(3))
                .until(activityStarted::get);

        engine.close();

        assertThat(activityCanceled).isTrue();
    }

    @Test
    void shouldPropagateExceptions() {
        final AtomicReference<FailureException> exceptionReference = new AtomicReference<>();

        registerWorkflow("foo", (ctx, arg) -> {
            try {
                ctx.callChildWorkflow("bar", 1, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            } catch (FailureException e) {
                exceptionReference.set(e);
                throw e;
            }

            return null;
        });
        registerWorkflow("bar", (ctx, arg) -> {
            ctx.callChildWorkflow("baz", 1, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("baz", (ctx, arg) -> {
            ctx.callActivity("qux", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("qux", (ctx, arg) -> {
            throw new TerminalApplicationFailureException("Ouch!", null);
        });
        registerWorkflowWorker("workflow-worker", 3);
        registerActivityWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE)
                .withLabels(Map.of("oof", "rab")));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED, Duration.ofSeconds(15));

        assertThat(exceptionReference.get()).satisfies(e -> {
            assertThat(e).isInstanceOf(ChildWorkflowFailureException.class);
            assertThat(e.getMessage()).matches("Run .+ of child workflow bar v1 failed");
            assertThat(e.getStackTrace()).isEmpty();

            {
                final var failure = (ChildWorkflowFailureException) e;
                assertThat(failure.getRunId()).isNotNull();
                assertThat(failure.getWorkflowName()).isEqualTo("bar");
                assertThat(failure.getWorkflowVersion()).isEqualTo(1);
            }

            assertThat(e.getCause()).satisfies(firstCause -> {
                assertThat(firstCause).isInstanceOf(ChildWorkflowFailureException.class);
                assertThat(firstCause.getMessage()).matches("Run .+ of child workflow baz v1 failed");
                assertThat(firstCause.getStackTrace()).isEmpty();

                {
                    final var failure = (ChildWorkflowFailureException) firstCause;
                    assertThat(failure.getRunId()).isNotNull();
                    assertThat(failure.getWorkflowName()).isEqualTo("baz");
                    assertThat(failure.getWorkflowVersion()).isEqualTo(1);
                }

                assertThat(firstCause.getCause()).satisfies(secondCause -> {
                    assertThat(secondCause).isInstanceOf(ActivityFailureException.class);
                    assertThat(secondCause.getMessage()).isEqualTo("Activity qux failed");
                    assertThat(secondCause.getStackTrace()).isEmpty();

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
        registerWorkflow("foo", (ctx, arg) -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            ctx.callChildWorkflow("bar", 1, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("bar", (ctx, arg) -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            return null;
        });
        registerWorkflowWorker("workflow-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE)
                        .withLabels(Map.of("oof", "123", "rab", "321")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED);
                    assertThat(entry.getRunCreated().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED);
                    assertThat(entry.getChildRunCreated().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldContinueAsNew() {
        registerWorkflow("foo", stringConverter(), stringConverter(), (ctx, arg) -> {
            final int iteration = Integer.parseInt(arg);
            ctx.executeSideEffect("abc-" + iteration, stringConverter(), () -> "def-" + iteration).await();
            if (iteration < 3) {
                ctx.continueAsNew(
                        new ContinueAsNewOptions<String>()
                                .withArgument(String.valueOf(iteration + 1)));
            }
            return String.valueOf(iteration);
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE)
                        .withArgument("0"));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunEvents(new ListWorkflowRunEventsRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED), // TODO: Get rid of this.
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED);
                    assertThat(stringConverter().convertFromPayload(entry.getRunCreated().getArgument())).isEqualTo("3");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(stringConverter().convertFromPayload(entry.getRunCompleted().getResult())).isEqualTo("3");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldInformEventListenersAboutCompletedRuns() {
        final var completedRuns = new ArrayList<WorkflowRunMetadata>();
        engine.addEventListener((WorkflowRunsCompletedEventListener) event -> {
            completedRuns.addAll(event.completedRuns());
        });

        registerWorkflow("foo", stringConverter(), stringConverter(), (ctx, arg) -> {
            final boolean shouldFail = Boolean.parseBoolean(arg);
            if (shouldFail) {
                throw new IllegalStateException();
            }

            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID succeedingRunId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE).withArgument("false"));
        final UUID failingRunId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE).withArgument("true"));

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
        registerWorkflow("test", (ctx, arg) -> null);

        for (int i = 0; i < 10; i++) {
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1, WORKFLOW_TASK_QUEUE));
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
        registerWorkflow("foo", (ctx, arg) -> {
            ctx.executeSideEffect("a", () -> {
            }).await();
            ctx.executeSideEffect("b", () -> {
            }).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1, WORKFLOW_TASK_QUEUE));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        Page<WorkflowEvent> historyPage = engine.listRunEvents(
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

    @Nested
    class WorkflowTaskQueueTest {

        @Test
        void createShouldReturnTrueWhenCreatedAndFalseWhenNot() {
            boolean created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo", 1));
            assertThat(created).isTrue();

            created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo", 2));
            assertThat(created).isFalse();
        }

        @Test
        void updateShouldReturnTrueWhenUpdated() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo", TaskQueueStatus.PAUSED, null));
            assertThat(updated).isTrue();
        }

        @Test
        void updateShouldReturnFalseWhenUnchanged() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo", null, null));
            assertThat(updated).isFalse();
        }

        @Test
        void updateShouldThrowWhenQueueDoesNotExist() {
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> engine.updateTaskQueue(
                            new UpdateTaskQueueRequest(TaskQueueType.WORKFLOW, "does-not-exist", null, null)));
        }

        @Test
        void listShouldSupportPagination() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo-1", 1));
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "foo-2", 2));

            Page<@NonNull TaskQueue> queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskQueueType.WORKFLOW).withLimit(2));
            assertThat(queuesPage.items()).satisfiesExactly(
                    queue -> {
                        assertThat(queue.name()).isEqualTo("default");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.maxConcurrency()).isEqualTo(10);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    },
                    queue -> {
                        assertThat(queue.name()).isEqualTo("foo-1");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.maxConcurrency()).isEqualTo(1);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    });
            assertThat(queuesPage.nextPageToken()).isNotNull();

            queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskQueueType.WORKFLOW).withPageToken(queuesPage.nextPageToken()));
            assertThat(queuesPage.items()).satisfiesExactly(queue -> {
                assertThat(queue.name()).isEqualTo("foo-2");
                assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                assertThat(queue.maxConcurrency()).isEqualTo(2);
                assertThat(queue.depth()).isEqualTo(0);
                assertThat(queue.createdAt()).isNotNull();
                assertThat(queue.updatedAt()).isNull();
            });
            assertThat(queuesPage.nextPageToken()).isNull();
        }

    }

    @Nested
    class TaskQueueTest {

        @Test
        void createShouldReturnTrueWhenCreatedAndFalseWhenNot() {
            boolean created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", 1));
            assertThat(created).isTrue();

            created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", 2));
            assertThat(created).isFalse();
        }

        @Test
        void updateShouldReturnTrueWhenUpdated() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", TaskQueueStatus.PAUSED, null));
            assertThat(updated).isTrue();
        }

        @Test
        void updateShouldReturnFalseWhenUnchanged() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", null, null));
            assertThat(updated).isFalse();
        }

        @Test
        void updateShouldThrowWhenQueueDoesNotExist() {
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> engine.updateTaskQueue(
                            new UpdateTaskQueueRequest(TaskQueueType.ACTIVITY, "does-not-exist", null, null)));
        }

        @Test
        void listShouldSupportPagination() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo-1", 1));
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo-2", 2));

            Page<@NonNull TaskQueue> queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskQueueType.ACTIVITY).withLimit(2));
            assertThat(queuesPage.items()).satisfiesExactly(
                    queue -> {
                        assertThat(queue.name()).isEqualTo("default");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.maxConcurrency()).isEqualTo(10);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    },
                    queue -> {
                        assertThat(queue.name()).isEqualTo("foo-1");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.maxConcurrency()).isEqualTo(1);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    });
            assertThat(queuesPage.nextPageToken()).isNotNull();

            queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskQueueType.ACTIVITY).withPageToken(queuesPage.nextPageToken()));
            assertThat(queuesPage.items()).satisfiesExactly(queue -> {
                assertThat(queue.name()).isEqualTo("foo-2");
                assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                assertThat(queue.maxConcurrency()).isEqualTo(2);
                assertThat(queue.depth()).isEqualTo(0);
                assertThat(queue.createdAt()).isNotNull();
                assertThat(queue.updatedAt()).isNull();
            });
            assertThat(queuesPage.nextPageToken()).isNull();
        }

    }

    @Nested
    class HealthProbeTest {

        @Test
        void shouldReportAsUpWhenRunning() {
            engine.start();

            final HealthCheckResponse response = engine.probeHealth();

            assertThat(response).isNotNull();
            assertThat(response.getName()).isEqualTo("dex-engine");
            assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
            assertThat(response.getData()).isPresent();
            assertThat(response.getData().get()).containsExactlyInAnyOrderEntriesOf(
                    Map.ofEntries(
                            Map.entry("internalStatus", "RUNNING"),
                            Map.entry("buffer:external-event", "RUNNING"),
                            Map.entry("buffer:task-event", "RUNNING")));
        }

        @Test
        void shouldReportAsDownWhenCreated() {
            final HealthCheckResponse response = engine.probeHealth();

            assertThat(response).isNotNull();
            assertThat(response.getName()).isEqualTo("dex-engine");
            assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
            assertThat(response.getData()).isPresent();
            assertThat(response.getData().get()).containsExactlyInAnyOrderEntriesOf(Map.of("internalStatus", "CREATED"));
        }

        @Test
        void shouldReportAsDownWhenStopped() throws Exception {
            engine.start();
            engine.close();

            final HealthCheckResponse response = engine.probeHealth();

            assertThat(response).isNotNull();
            assertThat(response.getName()).isEqualTo("dex-engine");
            assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
            assertThat(response.getData()).isPresent();
            assertThat(response.getData().get()).containsExactlyInAnyOrderEntriesOf(Map.of("internalStatus", "STOPPED"));
        }

    }

    private interface InternalWorkflowExecutor<A, R> extends WorkflowExecutor<A, R> {

        R execute(WorkflowContextImpl<A, R> ctx, A argument);

        @Override
        default R execute(WorkflowContext<A> ctx, A argument) {
            return execute((WorkflowContextImpl<A, R>) ctx, argument);
        }

    }

    private <A, R> void registerWorkflow(
            final String name,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final InternalWorkflowExecutor<A, R> executor) {
        engine.registerWorkflowInternal(name, 1, argumentConverter, resultConverter, WORKFLOW_TASK_QUEUE, Duration.ofSeconds(5), executor);
    }

    private void registerWorkflow(final String name, final InternalWorkflowExecutor<Void, Void> executor) {
        registerWorkflow(name, voidConverter(), voidConverter(), executor);
    }

    private <A, R> void registerActivity(
            final String name,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final ActivityExecutor<A, R> executor) {
        engine.registerActivityInternal(name, argumentConverter, resultConverter, ACTIVITY_TASK_QUEUE, Duration.ofSeconds(5), executor);
    }

    private void registerActivity(final String name, final ActivityExecutor<Void, Void> executor) {
        registerActivity(name, voidConverter(), voidConverter(), executor);
    }

    private void registerWorkflowWorker(final String name, final int maxConcurrency) {
        engine.registerWorkflowWorker(
                new WorkflowTaskWorkerOptions(name, WORKFLOW_TASK_QUEUE, maxConcurrency)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(1)));
    }

    private void registerActivityWorker(final String name, final int maxConcurrency) {
        engine.registerActivityWorker(
                new ActivityTaskWorkerOptions(name, ACTIVITY_TASK_QUEUE, maxConcurrency)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(1)));
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
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(15));
    }

}