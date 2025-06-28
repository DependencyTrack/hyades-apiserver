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
package org.dependencytrack.workflow.engine;

import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.Awaitable;
import org.dependencytrack.workflow.api.ContinueAsNewOptions;
import org.dependencytrack.workflow.api.failure.ActivityFailureException;
import org.dependencytrack.workflow.api.failure.ApplicationFailureException;
import org.dependencytrack.workflow.api.failure.SubWorkflowFailureException;
import org.dependencytrack.workflow.api.failure.WorkflowFailureException;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.engine.api.ActivityGroup;
import org.dependencytrack.workflow.engine.api.WorkflowEngineConfig;
import org.dependencytrack.workflow.engine.api.WorkflowGroup;
import org.dependencytrack.workflow.engine.api.WorkflowRun;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.WorkflowSchedule;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowScheduleRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowSchedulesRequest;
import org.dependencytrack.workflow.engine.payload.StringPayloadConverter;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.proto.workflow.api.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELLED;
import static org.dependencytrack.proto.workflow.api.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.proto.workflow.api.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;
import static org.dependencytrack.workflow.api.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.voidConverter;

@Testcontainers
class WorkflowEngineImplTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();

    private final PayloadConverter<String> stringConverter = new StringPayloadConverter();
    private WorkflowEngineImpl engine;

    @BeforeEach
    void beforeEach() {
        postgresContainer.truncateTables();

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        dataSource.setDatabaseName(postgresContainer.getDatabaseName());

        final var config = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
        config.scheduler().setInitialDelay(Duration.ofMillis(250));
        config.scheduler().setPollInterval(Duration.ofMillis(250));

        engine = new WorkflowEngineImpl(config);
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
        engine.registerWorkflowInternal("test", 1, stringConverter, stringConverter, Duration.ofSeconds(5), ctx -> {
            ctx.setStatus("someCustomStatus");
            return "someResult";
        });
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest("test", 1)
                        .withConcurrencyGroupId("someConcurrencyGroupId")
                        .withPriority(6)
                        .withLabels(Map.of("label-a", "123", "label-b", "321"))
                        .withArgument(stringConverter.convertToPayload("someArgument")));

        final WorkflowRun completedRun = awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(completedRun.customStatus()).isEqualTo("someCustomStatus");
        assertThat(completedRun.concurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
        assertThat(completedRun.priority()).isEqualTo(6);
        assertThat(completedRun.labels()).containsOnlyKeys("label-a", "label-b");
        assertThat(completedRun.createdAt()).isNotNull();
        assertThat(completedRun.updatedAt()).isNotNull();
        assertThat(completedRun.startedAt()).isNotNull();
        assertThat(completedRun.completedAt()).isNotNull();

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED);
                    assertThat(event.getRunScheduled().getWorkflowName()).isEqualTo("test");
                    assertThat(event.getRunScheduled().getWorkflowVersion()).isEqualTo(1);
                    assertThat(event.getRunScheduled().getConcurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
                    assertThat(event.getRunScheduled().getPriority()).isEqualTo(6);
                    assertThat(event.getRunScheduled().getLabelsMap()).containsOnlyKeys("label-a", "label-b");
                    assertThat(event.getRunScheduled().getArgument().hasBinaryContent()).isTrue();
                    assertThat(event.getRunScheduled().getArgument().getBinaryContent().getData().toStringUtf8()).isEqualTo("someArgument");
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

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    void shouldFailWorkflowRunWhenRunnerThrows() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Ouch!");
        });
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        final WorkflowRun failedRun = awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(failedRun.customStatus()).isNull();
        assertThat(failedRun.concurrencyGroupId()).isNull();
        assertThat(failedRun.priority()).isNull();
        assertThat(failedRun.labels()).isNull();
        assertThat(failedRun.createdAt()).isNotNull();
        assertThat(failedRun.updatedAt()).isNotNull();
        assertThat(failedRun.startedAt()).isNotNull();
        assertThat(failedRun.completedAt()).isNotNull();

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().hasResult()).isFalse();
                    assertThat(event.getRunCompleted().getFailure().getMessage()).isEqualTo("Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    void shouldFailWorkflowRunWhenCancelled() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(5)).await();
            return null;
        });
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        engine.requestRunCancellation(runId, "Stop it!");

        final WorkflowRun cancelledRun = awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);

        assertThat(cancelledRun.customStatus()).isNull();
        assertThat(cancelledRun.concurrencyGroupId()).isNull();
        assertThat(cancelledRun.priority()).isNull();
        assertThat(cancelledRun.labels()).isNull();
        assertThat(cancelledRun.createdAt()).isNotNull();
        assertThat(cancelledRun.updatedAt()).isNotNull();
        assertThat(cancelledRun.startedAt()).isNotNull();
        assertThat(cancelledRun.completedAt()).isNotNull();

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CANCELLED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_CANCELLED);
                    assertThat(entry.getRunCompleted().hasResult()).isFalse();
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Stop it!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    void shouldWaitForScheduledTimerToElapse() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.scheduleTimer("Sleep for 3 seconds", Duration.ofSeconds(5)).await();
            return null;
        });
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED);
                    assertThat(entry.getTimerScheduled().getName()).isEqualTo("Sleep for 3 seconds");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    void shouldWaitForMultipleScheduledTimersToElapse() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final var timers = new ArrayList<Awaitable<Void>>(3);
            for (int i = 0; i < 3; i++) {
                timers.add(ctx.scheduleTimer("sleep" + i, Duration.ofSeconds(3)));
            }

            for (final Awaitable<Void> timer : timers) {
                timer.await();
            }

            return null;
        });
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(15)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    void shouldWaitForSubWorkflowRun() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final String subWorkflowResult = ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow(
                    "bar", 1, null, "inputValue", stringConverter, stringConverter).await();
            assertThat(subWorkflowResult).contains("inputValue-outputValue");
            return null;
        });

        engine.registerWorkflowInternal("bar", 1, stringConverter, stringConverter, Duration.ofSeconds(5),
                ctx -> ctx.argument() + "-outputValue");

        engine.mount(new WorkflowGroup("test-group")
                .withWorkflow("foo")
                .withWorkflow("bar")
                .withMaxConcurrency(2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWhenSubWorkflowRunFails() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Oh no!");
        });

        engine.mount(new WorkflowGroup("test-group")
                .withWorkflow("foo")
                .withWorkflow("bar")
                .withMaxConcurrency(2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_FAILED);
                    assertThat(entry.getSubWorkflowRunFailed().getFailure().getMessage()).isEqualTo("Oh no!");
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().hasMessage()).isFalse();
                    assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Oh no!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCancelSubWorkflowRunsRecursivelyWhenParentRunIsCancelled() {
        final var childRunIdReference = new AtomicReference<UUID>();
        final var grandChildRunIdReference = new AtomicReference<UUID>();

        engine.registerWorkflowInternal("parent", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow("child", 1, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            childRunIdReference.set(ctx.runId());
            ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow("grand-child", 1, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("grand-child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            grandChildRunIdReference.set(ctx.runId());
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group")
                .withWorkflow("parent")
                .withWorkflow("child")
                .withWorkflow("grand-child")
                .withMaxConcurrency(3));
        engine.start();

        final UUID parentRunId = engine.createRun(new CreateWorkflowRunRequest("parent", 1));

        await("Grand Child Workflow Run Start")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(grandChildRunIdReference.get()).isNotNull());

        engine.requestRunCancellation(parentRunId, "someReason");

        awaitRunStatus(parentRunId, WorkflowRunStatus.CANCELLED);
        awaitRunStatus(childRunIdReference.get(), WorkflowRunStatus.CANCELLED);
        awaitRunStatus(grandChildRunIdReference.get(), WorkflowRunStatus.CANCELLED);
    }

    @Test
    void shouldThrowWhenCancellingRunInTerminalState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> null);
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunCancellation(runId, "someReason"))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldSuspendAndResumeRunWhenRequested() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunResumption(runId);

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
    }

    @Test
    void shouldCancelSuspendedRunWhenRequested() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunCancellation(runId, "someReason");

        awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);
    }

    @Test
    void shouldThrowWhenSuspendingRunInTerminalState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> null);
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldThrowWhenSuspendingRunInSuspendedState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInNonSuspendedState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to act on the running run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ can not be resumed because it is not suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInTerminalState() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> null);
        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldWaitForExternalEvent() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRun run = engine.getRun(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(runId, "foo-123", null).join();

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXTERNAL_EVENT_RECEIVED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldFailWhenWaitingForExternalEventTimesOut() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofMillis(5)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
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

    @Test
    void shouldRecordSideEffectResult() {
        final var sideEffectInvocationCounter = new AtomicInteger();

        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect("sideEffect", null, voidConverter(), ignored -> {
                sideEffectInvocationCounter.incrementAndGet();
                return null;
            }).await();

            ctx.scheduleTimer("sleep", Duration.ofMillis(10)).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED);
                    assertThat(entry.getSideEffectExecuted().getName()).isEqualTo("sideEffect");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldNotAllowNestedSideEffects() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect("outerSideEffect", null, voidConverter(), ignored -> {
                ctx.sideEffect("nestedSideEffect", null, voidConverter(), ignored2 -> null).await();
                return null;
            }).await();

            return null;
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getCause().hasSideEffectFailureDetails());
                    assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Nested side effects are not allowed");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldCallActivity() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                    "abc", null, voidConverter(), stringConverter, defaultRetryPolicy()).await();
            return null;
        });

        engine.registerActivityInternal("abc", voidConverter(), stringConverter, Duration.ofSeconds(5), false, ctx -> "123");

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.mount(new ActivityGroup("test-group").withActivity("abc"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldScheduleMultipleActivitiesConcurrently() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), stringConverter, Duration.ofSeconds(5), ctx -> {
            final List<Awaitable<String>> awaitables = List.of(
                    ((WorkflowContextImpl<?, ?>) ctx).callActivity("abc", "first", stringConverter, stringConverter, defaultRetryPolicy()),
                    ((WorkflowContextImpl<?, ?>) ctx).callActivity("abc", "second", stringConverter, stringConverter, defaultRetryPolicy()));

            return awaitables.stream()
                    .map(Awaitable::await)
                    .collect(Collectors.joining(", "));
        });

        engine.registerActivityInternal("abc", stringConverter, stringConverter, Duration.ofSeconds(5), false, ActivityContext::argument);

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.mount(new ActivityGroup("test-group").withActivity("abc").withMaxConcurrency(2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(15)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldRetryFailingActivity() {
        final var retryPolicy = defaultRetryPolicy()
                .withMaxDelay(Duration.ofMillis(10))
                .withMaxAttempts(3);

        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                    "abc", null, voidConverter(), stringConverter, retryPolicy).await();
            return null;
        });

        engine.registerActivityInternal("abc", voidConverter(), stringConverter, Duration.ofSeconds(5), false, ctx -> {
            throw new IllegalStateException();
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.mount(new ActivityGroup("test-group").withActivity("abc"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(20)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldNotRetryActivityFailingWithTerminalException() {
        engine.registerWorkflowInternal("test", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity(
                    "abc", null, voidConverter(), stringConverter, defaultRetryPolicy()).await();
            return null;
        });

        engine.registerActivityInternal("abc", voidConverter(), stringConverter, Duration.ofSeconds(5), false, ctx -> {
            throw new ApplicationFailureException("Ouch!", null, true);
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("test"));
        engine.mount(new ActivityGroup("test-group").withActivity("abc"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
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
    void shouldPropagateExceptions() {
        final AtomicReference<WorkflowFailureException> exceptionReference = new AtomicReference<>();

        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            try {
                ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            } catch (WorkflowFailureException e) {
                exceptionReference.set(e);
                throw e;
            }

            return null;
        });

        engine.registerWorkflowInternal("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow("baz", 1, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("baz", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ((WorkflowContextImpl<?, ?>) ctx).callActivity("qux", null, voidConverter(), voidConverter(), defaultRetryPolicy()).await();
            return null;
        });

        engine.registerActivityInternal("qux", voidConverter(), voidConverter(), Duration.ofSeconds(5), false, ctx -> {
            throw new ApplicationFailureException("Ouch!", null, true);
        });

        engine.mount(new WorkflowGroup("test-group")
                .withWorkflow("foo")
                .withWorkflow("bar")
                .withWorkflow("baz")
                .withMaxConcurrency(3));
        engine.mount(new ActivityGroup("test-group").withActivity("qux"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("foo", 1)
                .withLabels(Map.of("oof", "rab")));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED, Duration.ofSeconds(15));

        assertThat(exceptionReference.get()).satisfies(e -> {
            assertThat(e).isInstanceOf(SubWorkflowFailureException.class);
            assertThat(e.getMessage()).matches("Run .+ of workflow bar v1 failed");
            assertThat(e.getStackTrace()).isNotEmpty();

            {
                final var failure = (SubWorkflowFailureException) e;
                assertThat(failure.getRunId()).isNotNull();
                assertThat(failure.getWorkflowName()).isEqualTo("bar");
                assertThat(failure.getWorkflowVersion()).isEqualTo(1);
            }

            assertThat(e.getCause()).satisfies(firstCause -> {
                assertThat(firstCause).isInstanceOf(SubWorkflowFailureException.class);
                assertThat(firstCause.getMessage()).matches("Run .+ of workflow baz v1 failed");
                assertThat(firstCause.getStackTrace()).isNotEmpty();

                {
                    final var failure = (SubWorkflowFailureException) firstCause;
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
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            ((WorkflowContextImpl<?, ?>) ctx).callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return null;
        });

        engine.registerWorkflowInternal("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            return null;
        });

        engine.mount(new WorkflowGroup("test-group")
                .withWorkflow("foo")
                .withWorkflow("bar")
                .withMaxConcurrency(2));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("foo", 1)
                .withLabels(Map.of("oof", "123", "rab", "321")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED);
                    assertThat(entry.getRunScheduled().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED);
                    assertThat(entry.getSubWorkflowRunScheduled().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldContinueAsNew() {
        engine.registerWorkflowInternal("foo", 1, stringConverter, stringConverter, Duration.ofSeconds(5), ctx -> {
            final int iteration = Integer.parseInt(ctx.argument());
            ctx.sideEffect("abc-" + iteration, null, stringConverter, ignored -> "def-" + iteration).await();
            if (iteration < 3) {
                ctx.continueAsNew(
                        new ContinueAsNewOptions<String>()
                                .withArgument(String.valueOf(iteration + 1)));
            }
            return String.valueOf(iteration);
        });

        engine.mount(new WorkflowGroup("test-group").withWorkflow("foo"));
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest("foo", 1)
                        .withArgument(stringConverter.convertToPayload("0")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.listRunHistory(new ListWorkflowRunHistoryRequest(runId)).items()).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED), // TODO: Get rid of this.
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED);
                    assertThat(stringConverter.convertFromPayload(entry.getRunScheduled().getArgument())).isEqualTo("3");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(stringConverter.convertFromPayload(entry.getRunCompleted().getResult())).isEqualTo("3");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_COMPLETED));
    }

    @Test
    void shouldSupportWorkflowVersioning() {
        // TODO
    }

    @Test
    void shouldCreateRuns() {
        final List<WorkflowSchedule> createdSchedules = engine.createSchedules(List.of(
                new CreateWorkflowScheduleRequest("foo-schedule", "* * * * *", "foo", 1)
                        .withConcurrencyGroupId("concurrencyGroupId")
                        .withPriority(666)
                        .withLabels(Map.of("label", "123"))
                        .withInitialDelay(Duration.ZERO)));
        engine.start();

        assertThat(createdSchedules).satisfiesExactly(schedule -> {
            assertThat(schedule.name()).isEqualTo("foo-schedule");
            assertThat(schedule.cron()).isEqualTo("* * * * *");
            assertThat(schedule.workflowName()).isEqualTo("foo");
            assertThat(schedule.workflowVersion()).isEqualTo(1);
            assertThat(schedule.concurrencyGroupId()).isEqualTo("concurrencyGroupId");
            assertThat(schedule.priority()).isEqualTo(666);
            assertThat(schedule.labels()).containsOnlyKeys("label");
            assertThat(schedule.argument()).isNull();
            assertThat(schedule.createdAt()).isNotNull();
            assertThat(schedule.updatedAt()).isNull();
            assertThat(schedule.lastFiredAt()).isNull();
            assertThat(schedule.nextFireAt()).isNotNull();
        });

        final Page<WorkflowRun> runsPage = await("Workflow Run to be scheduled")
                .atMost(Duration.ofSeconds(5))
                .until(() -> engine.listRuns(new ListWorkflowRunsRequest()), page -> !page.items().isEmpty());

        assertThat(runsPage.items()).satisfiesExactly(run -> {
            assertThat(run.workflowName()).isEqualTo("foo");
            assertThat(run.workflowVersion()).isEqualTo(1);
            assertThat(run.status()).isEqualTo(WorkflowRunStatus.PENDING);
            assertThat(run.concurrencyGroupId()).isEqualTo("concurrencyGroupId");
            assertThat(run.priority()).isEqualTo(666);
            assertThat(run.labels()).containsExactlyInAnyOrderEntriesOf(Map.ofEntries(
                    Map.entry("label", "123"),
                    Map.entry("schedule", "foo-schedule")));
        });
    }

    @Test
    void shouldNotCreateSchedulesWhenAlreadyExist() {
        engine.createSchedules(List.of(
                new CreateWorkflowScheduleRequest("foo-schedule", "* * * * *", "foo", 1)));

        final List<WorkflowSchedule> createdSchedules = engine.createSchedules(List.of(
                new CreateWorkflowScheduleRequest("foo-schedule", "1 1 1 1 1", "oof", 9),
                new CreateWorkflowScheduleRequest("bar-schedule", "* * * * *", "bar", 1)));

        assertThat(createdSchedules).satisfiesExactly(schedule -> {
            assertThat(schedule.name()).isEqualTo("bar-schedule");
        });
    }

    @Test
    void shouldListRuns() {
        for (int i = 0; i < 10; i++) {
            engine.createRun(new CreateWorkflowRunRequest("test", 1));
        }

        final Page<WorkflowRun> firstRunsPage = engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLimit(5));
        assertThat(firstRunsPage.items()).hasSize(5);
        assertThat(firstRunsPage.currentPageToken()).isNull();
        assertThat(firstRunsPage.nextPageToken()).isNotNull();

        final Page<WorkflowRun> secondRunsPage = engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withPageToken(firstRunsPage.nextPageToken())
                        .withLimit(5));
        assertThat(secondRunsPage.items()).hasSize(5);
        assertThat(secondRunsPage.currentPageToken()).isEqualTo(firstRunsPage.nextPageToken());
        assertThat(secondRunsPage.nextPageToken()).isNull();
    }

    @Test
    void shouldListSchedules() {
        for (int i = 0; i < 10; i++) {
            engine.createSchedule(
                    new CreateWorkflowScheduleRequest(
                            "schedule-" + i, "* * * * *", "workflow-foo", 1));
        }

        final Page<WorkflowSchedule> firstSchedulesPage = engine.listSchedules(
                new ListWorkflowSchedulesRequest()
                        .withLimit(5));
        assertThat(firstSchedulesPage.items()).hasSize(5);
        assertThat(firstSchedulesPage.currentPageToken()).isNull();
        assertThat(firstSchedulesPage.nextPageToken()).isNotNull();

        final Page<WorkflowSchedule> secondSchedulesPage = engine.listSchedules(
                new ListWorkflowSchedulesRequest()
                        .withPageToken(firstSchedulesPage.nextPageToken())
                        .withLimit(5));
        assertThat(secondSchedulesPage.items()).hasSize(5);
        assertThat(secondSchedulesPage.currentPageToken()).isEqualTo(firstSchedulesPage.nextPageToken());
        assertThat(secondSchedulesPage.nextPageToken()).isNull();
    }

    @Test
    void shouldListRunHistory() {
        engine.registerWorkflowInternal("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect("a", null, voidConverter(), ignored -> null).await();
            ctx.sideEffect("b", null, voidConverter(), ignored -> null).await();
            return null;
        });

        engine.mount(new WorkflowGroup("test").withWorkflow("foo"));
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final Page<WorkflowEvent> firstHistoryPage = engine.listRunHistory(
                new ListWorkflowRunHistoryRequest(runId)
                        .withLimit(3));
        assertThat(firstHistoryPage.items()).satisfiesExactly(
                event -> assertThat(event.hasExecutionStarted()).isTrue(),
                event -> assertThat(event.hasRunScheduled()).isTrue(),
                event -> assertThat(event.hasRunStarted()).isTrue());
        assertThat(firstHistoryPage.currentPageToken()).isNull();
        assertThat(firstHistoryPage.nextPageToken()).isNotNull();

        final Page<WorkflowEvent> secondHistoryPage = engine.listRunHistory(
                new ListWorkflowRunHistoryRequest(runId)
                        .withPageToken(firstHistoryPage.nextPageToken())
                        .withLimit(2));
        assertThat(secondHistoryPage.items()).satisfiesExactly(
                event -> assertThat(event.hasSideEffectExecuted()).isTrue(),
                event -> assertThat(event.hasSideEffectExecuted()).isTrue());
        assertThat(secondHistoryPage.currentPageToken()).isEqualTo(firstHistoryPage.nextPageToken());
        assertThat(secondHistoryPage.nextPageToken()).isNotNull();
    }

    private WorkflowRun awaitRunStatus(
            final UUID runId,
            final WorkflowRunStatus expectedStatus,
            final Duration timeout) {
        return await("Workflow Run Status to become " + expectedStatus)
                .atMost(timeout)
                .failFast(() -> {
                    final WorkflowRunStatus currentStatus = engine.getRun(runId).status();
                    if (currentStatus.isTerminal() && !expectedStatus.isTerminal()) {
                        return true;
                    }

                    return currentStatus.isTerminal()
                           && expectedStatus.isTerminal()
                           && currentStatus != expectedStatus;
                })
                .until(() -> engine.getRun(runId), run -> run.status() == expectedStatus);
    }

    private WorkflowRun awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(5));
    }

}