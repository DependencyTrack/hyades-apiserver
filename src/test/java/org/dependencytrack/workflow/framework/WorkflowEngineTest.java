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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.framework.failure.ActivityFailureException;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.dependencytrack.workflow.framework.failure.SubWorkflowFailureException;
import org.dependencytrack.workflow.framework.failure.WorkflowFailureException;
import org.dependencytrack.workflow.framework.persistence.model.WorkflowRunListRow;
import org.dependencytrack.workflow.framework.persistence.model.WorkflowScheduleRow;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELLED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;
import static org.dependencytrack.workflow.framework.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

public class WorkflowEngineTest extends PersistenceCapableTest {

    private WorkflowEngine engine;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        final DataSource dataSource = PersistenceUtil.getDataSource(qm.getPersistenceManager());

        final var config = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
        config.scheduler().setInitialDelay(Duration.ofMillis(250));
        config.scheduler().setPollInterval(Duration.ofMillis(250));

        engine = new WorkflowEngine(config);
        engine.start();
    }

    @After
    @Override
    public void after() {
        if (engine != null) {
            try {
                engine.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        super.after();
    }

    @Test
    public void shouldRunWorkflowWithArgumentAndResult() {
        engine.registerWorkflowExecutor("foo", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.setStatus("someCustomStatus");
            return Optional.of("someResult");
        });

        final UUID runId = engine.scheduleWorkflowRun(
                new ScheduleWorkflowRunOptions("foo", 1)
                        .withConcurrencyGroupId("someConcurrencyGroupId")
                        .withPriority(6)
                        .withLabels(Map.of("label-a", "123", "label-b", "321"))
                        .withArgument("someArgument", stringConverter()));

        final WorkflowRunStateView completedRun = awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(completedRun.customStatus()).isEqualTo("someCustomStatus");
        assertThat(completedRun.concurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
        assertThat(completedRun.priority()).isEqualTo(6);
        assertThat(completedRun.labels()).containsOnlyKeys("label-a", "label-b");
        assertThat(completedRun.createdAt()).isNotNull();
        assertThat(completedRun.updatedAt()).isNotNull();
        assertThat(completedRun.startedAt()).isNotNull();
        assertThat(completedRun.completedAt()).isNotNull();

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXECUTION_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED);
                    assertThat(event.getRunScheduled().getWorkflowName()).isEqualTo("foo");
                    assertThat(event.getRunScheduled().getWorkflowVersion()).isEqualTo(1);
                    assertThat(event.getRunScheduled().getConcurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
                    assertThat(event.getRunScheduled().getPriority()).isEqualTo(6);
                    assertThat(event.getRunScheduled().getLabelsMap()).containsOnlyKeys("label-a", "label-b");
                    assertThat(event.getRunScheduled().getArgument().hasBinaryContent()).isTrue();
                    assertThat(event.getRunScheduled().getArgument().getBinaryContent().toStringUtf8()).isEqualTo("someArgument");
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
                    assertThat(event.getRunCompleted().getResult().getBinaryContent().toStringUtf8()).isEqualTo("someResult");
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
    public void shouldFailWorkflowRunWhenRunnerThrows() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Ouch!");
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        final WorkflowRunStateView failedRun = awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(failedRun.customStatus()).isNull();
        assertThat(failedRun.concurrencyGroupId()).isNull();
        assertThat(failedRun.priority()).isNull();
        assertThat(failedRun.labels()).isNull();
        assertThat(failedRun.createdAt()).isNotNull();
        assertThat(failedRun.updatedAt()).isNotNull();
        assertThat(failedRun.startedAt()).isNotNull();
        assertThat(failedRun.completedAt()).isNotNull();

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldFailWorkflowRunWhenCancelled() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        engine.cancelWorkflowRun(runId, "Stop it!");

        final WorkflowRunStateView cancelledRun = awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);

        assertThat(cancelledRun.customStatus()).isNull();
        assertThat(cancelledRun.concurrencyGroupId()).isNull();
        assertThat(cancelledRun.priority()).isNull();
        assertThat(cancelledRun.labels()).isNull();
        assertThat(cancelledRun.createdAt()).isNotNull();
        assertThat(cancelledRun.updatedAt()).isNotNull();
        assertThat(cancelledRun.startedAt()).isNotNull();
        assertThat(cancelledRun.completedAt()).isNotNull();

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldWaitForScheduledTimerToElapse() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.scheduleTimer("Sleep for 3 seconds", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldWaitForMultipleScheduledTimersToElapse() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final var timers = new ArrayList<Awaitable<Void>>(3);
            for (int i = 0; i < 3; i++) {
                timers.add(ctx.scheduleTimer("sleep" + i, Duration.ofSeconds(3)));
            }

            for (final Awaitable<Void> timer : timers) {
                timer.await();
            }

            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldWaitForSubWorkflowRun() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final Optional<String> subWorkflowResult = ctx.callSubWorkflow(
                    "bar", 1, null, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(subWorkflowResult).contains("inputValue-outputValue");
            return Optional.empty();
        });

        engine.registerWorkflowExecutor("bar", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5),
                ctx -> ctx.argument().map(argument -> argument + "-outputValue"));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldFailWhenSubWorkflowRunFails() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowExecutor("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Oh no!");
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldCancelSubWorkflowRunsRecursivelyWhenParentRunIsCancelled() {
        final var childRunIdReference = new AtomicReference<UUID>();
        final var grandChildRunIdReference = new AtomicReference<UUID>();

        engine.registerWorkflowExecutor("parent", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callSubWorkflow("child", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowExecutor("child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            childRunIdReference.set(ctx.runId());
            ctx.callSubWorkflow("grand-child", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowExecutor("grand-child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            grandChildRunIdReference.set(ctx.runId());
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID parentRunId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("parent", 1));

        await("Grand Child Workflow Run Start")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(grandChildRunIdReference.get()).isNotNull());

        engine.cancelWorkflowRun(parentRunId, "someReason");

        awaitRunStatus(parentRunId, WorkflowRunStatus.CANCELLED);
        awaitRunStatus(childRunIdReference.get(), WorkflowRunStatus.CANCELLED);
        awaitRunStatus(grandChildRunIdReference.get(), WorkflowRunStatus.CANCELLED);
    }

    @Test
    public void shouldThrowWhenCancellingRunInTerminalState() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> Optional.empty());

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.cancelWorkflowRun(runId, "someReason"))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    public void shouldSuspendAndResumeRunWhenRequested() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        engine.suspendWorkflowRun(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.resumeWorkflowRun(runId);

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
    }

    @Test
    public void shouldCancelSuspendedRunWhenRequested() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        engine.suspendWorkflowRun(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.cancelWorkflowRun(runId, "someReason");

        awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);
    }

    @Test
    public void shouldThrowWhenSuspendingRunInTerminalState() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> Optional.empty());

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.suspendWorkflowRun(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    public void shouldThrowWhenSuspendingRunInSuspendedState() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        engine.suspendWorkflowRun(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.suspendWorkflowRun(runId))
                .withMessageMatching("Workflow run .+ is already suspended");
    }

    @Test
    public void shouldThrowWhenResumingRunInNonSuspendedState() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to act on the running run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.resumeWorkflowRun(runId))
                .withMessageMatching("Workflow run .+ can not be resumed because it is not suspended");
    }

    @Test
    public void shouldThrowWhenResumingRunInTerminalState() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> Optional.empty());

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.resumeWorkflowRun(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    public void shouldWaitForExternalEvent() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunStateView run = engine.getRun(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(runId, "foo-123", null).join();

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldFailWhenWaitingForExternalEventTimesOut() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofMillis(5)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldRecordSideEffectResult() {
        final var sideEffectInvocationCounter = new AtomicInteger();

        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect("sideEffect", null, voidConverter(), ignored -> {
                sideEffectInvocationCounter.incrementAndGet();
                return null;
            }).await();

            ctx.scheduleTimer("sleep", Duration.ofMillis(10)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldNotAllowNestedSideEffects() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect("outerSideEffect", null, voidConverter(), ignored -> {
                ctx.sideEffect("nestedSideEffect", null, voidConverter(), ignored2 -> null).await();
                return null;
            }).await();

            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldCallActivity() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity(
                    "abc", null, voidConverter(), stringConverter(), defaultRetryPolicy()).await().orElseThrow();
            return Optional.empty();
        });

        engine.registerActivityExecutor("abc", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> Optional.of("123"));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldScheduleMultipleActivitiesConcurrently() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            final List<Awaitable<String>> awaitables = List.of(
                    ctx.callActivity("abc", "first", stringConverter(), stringConverter(), defaultRetryPolicy()),
                    ctx.callActivity("abc", "second", stringConverter(), stringConverter(), defaultRetryPolicy()));

            final String joinedResult = awaitables.stream()
                    .map(Awaitable::await)
                    .map(Optional::get)
                    .collect(Collectors.joining(", "));

            return Optional.of(joinedResult);
        });

        engine.registerActivityExecutor("abc", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5),
                ctx -> Optional.of(ctx.argument().orElseThrow()));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldRetryFailingActivity() {
        final var retryPolicy = defaultRetryPolicy()
                .withMaxDelay(Duration.ofMillis(10))
                .withMaxAttempts(3);

        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity(
                    "abc", null, voidConverter(), stringConverter(), retryPolicy).await().orElseThrow();
            return Optional.empty();
        });

        engine.registerActivityExecutor("abc", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldNotRetryActivityFailingWithTerminalException() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity(
                    "abc", null, voidConverter(), stringConverter(), defaultRetryPolicy()).await().orElseThrow();
            return Optional.empty();
        });

        engine.registerActivityExecutor("abc", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            throw new ApplicationFailureException("Ouch!", null, true);
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldPropagateExceptions() {
        final AtomicReference<WorkflowFailureException> exceptionReference = new AtomicReference<>();

        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            try {
                ctx.callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            } catch (WorkflowFailureException e) {
                exceptionReference.set(e);
                throw e;
            }

            return Optional.empty();
        });

        engine.registerWorkflowExecutor("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callSubWorkflow("baz", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowExecutor("baz", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity("qux", null, voidConverter(), voidConverter(), defaultRetryPolicy()).await();
            return Optional.empty();
        });

        engine.registerActivityExecutor("qux", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new ApplicationFailureException("Ouch!", null, true);
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1)
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
                    assertThat(secondCause.getMessage()).isEqualTo("Activity qux v-1 failed");
                    assertThat(secondCause.getStackTrace()).isNotEmpty();

                    {
                        final var failure = (ActivityFailureException) secondCause;
                        assertThat(failure.getActivityName()).isEqualTo("qux");
                        assertThat(failure.getActivityVersion()).isEqualTo(-1);
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
    public void shouldPropagateLabels() {
        engine.registerWorkflowExecutor("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            ctx.callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowExecutor("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1)
                .withLabels(Map.of("oof", "123", "rab", "321")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
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
    public void shouldSupportWorkflowVersioning() {
        // TODO
    }

    @Test
    public void shouldScheduleWorkflowRuns() {
        final List<WorkflowScheduleRow> createdSchedules = engine.createSchedules(List.of(
                new NewWorkflowSchedule("foo-schedule", "* * * * *", "foo", 1, "concurrencyGroupId", 666, Map.of("label", "123"), null, Duration.ZERO)));

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

        final List<WorkflowRunListRow> runs = await("Workflow Run to be scheduled")
                .atMost(Duration.ofSeconds(5))
                .until(() -> engine.getRunListPage(null, null, null, null, null, null, 0, 1), runsPage -> !runsPage.isEmpty());

        assertThat(runs).satisfiesExactly(run -> {
            assertThat(run.workflowName()).isEqualTo("foo");
            assertThat(run.workflowVersion()).isEqualTo(1);
            assertThat(run.status()).isEqualTo(WorkflowRunStatus.PENDING);
            assertThat(run.concurrencyGroupId()).isEqualTo("concurrencyGroupId");
            assertThat(run.priority()).isEqualTo(666);
            assertThat(run.labels()).containsExactlyEntriesOf(Map.ofEntries(
                    Map.entry("label", "123"),
                    Map.entry("schedule", "foo-schedule")));
        });
    }

    @Test
    public void shouldNotCreateSchedulesWhenAlreadyExist() {
        engine.createSchedules(List.of(
                new NewWorkflowSchedule("foo-schedule", "* * * * *", "foo", 1, null, null, null, null, null)));

        final List<WorkflowScheduleRow> createdSchedules = engine.createSchedules(List.of(
                new NewWorkflowSchedule("foo-schedule", "1 1 1 1 1", "oof", 9, null, null, null, null, null),
                new NewWorkflowSchedule("bar-schedule", "* * * * *", "bar", 1, null, null, null, null, null)));

        assertThat(createdSchedules).satisfiesExactly(schedule -> {
            assertThat(schedule.name()).isEqualTo("bar-schedule");
        });
    }

    private WorkflowRunStateView awaitRunStatus(
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

    private WorkflowRunStateView awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(5));
    }

}