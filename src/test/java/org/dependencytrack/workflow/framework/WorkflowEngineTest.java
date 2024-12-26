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
import org.dependencytrack.workflow.framework.persistence.model.WorkflowRunRow;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
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

        engine = new WorkflowEngine(new WorkflowEngineConfig(
                UUID.randomUUID(),
                PersistenceUtil.getDataSource(qm.getPersistenceManager())));
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
        engine.registerWorkflowRunner("foo", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.setStatus("someCustomStatus");
            return Optional.of("someResult");
        });

        final UUID runId = engine.scheduleWorkflowRun(
                new ScheduleWorkflowRunOptions("foo", 1)
                        .withConcurrencyGroupId("someConcurrencyGroupId")
                        .withPriority(6)
                        .withTags(Set.of("tag-a", "tag-b"))
                        .withArgument("someArgument", stringConverter()));

        final WorkflowRunRow completedRun = awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(completedRun.customStatus()).isEqualTo("someCustomStatus");
        assertThat(completedRun.concurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
        assertThat(completedRun.priority()).isEqualTo(6);
        assertThat(completedRun.tags()).containsExactlyInAnyOrder("tag-a", "tag-b");
        assertThat(completedRun.lockedBy()).isNull();
        assertThat(completedRun.lockedUntil()).isNull();
        assertThat(completedRun.createdAt()).isNotNull();
        assertThat(completedRun.updatedAt()).isNotNull();
        assertThat(completedRun.startedAt()).isNotNull();
        assertThat(completedRun.completedAt()).isNotNull();

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED);
                    assertThat(event.getRunScheduled().getWorkflowName()).isEqualTo("foo");
                    assertThat(event.getRunScheduled().getWorkflowVersion()).isEqualTo(1);
                    assertThat(event.getRunScheduled().getConcurrencyGroupId()).isEqualTo("someConcurrencyGroupId");
                    assertThat(event.getRunScheduled().getPriority()).isEqualTo(6);
                    assertThat(event.getRunScheduled().getTagsList()).containsExactlyInAnyOrder("tag-a", "tag-b");
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
                    assertThat(event.getRunCompleted().hasFailureDetails()).isFalse();
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED);
                });

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    public void shouldFailWorkflowRunWhenRunnerThrows() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Ouch!");
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        final WorkflowRunRow failedRun = awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(failedRun.customStatus()).isNull();
        assertThat(failedRun.concurrencyGroupId()).isNull();
        assertThat(failedRun.priority()).isNull();
        assertThat(failedRun.tags()).isNull();
        assertThat(failedRun.lockedBy()).isNull();
        assertThat(failedRun.lockedUntil()).isNull();
        assertThat(failedRun.createdAt()).isNotNull();
        assertThat(failedRun.updatedAt()).isNotNull();
        assertThat(failedRun.startedAt()).isNotNull();
        assertThat(failedRun.completedAt()).isNotNull();

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().hasResult()).isFalse();
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("IllegalStateException: Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    public void shouldFailWorkflowRunWhenCancelled() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        engine.cancelWorkflowRun(runId, "Stop it!");

        final WorkflowRunRow cancelledRun = awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);

        assertThat(cancelledRun.customStatus()).isNull();
        assertThat(cancelledRun.concurrencyGroupId()).isNull();
        assertThat(cancelledRun.priority()).isNull();
        assertThat(cancelledRun.tags()).isNull();
        assertThat(cancelledRun.lockedBy()).isNull();
        assertThat(cancelledRun.lockedUntil()).isNull();
        assertThat(cancelledRun.createdAt()).isNotNull();
        assertThat(cancelledRun.updatedAt()).isNotNull();
        assertThat(cancelledRun.startedAt()).isNotNull();
        assertThat(cancelledRun.completedAt()).isNotNull();

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CANCELLED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_CANCELLED);
                    assertThat(event.getRunCompleted().hasResult()).isFalse();
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("Stop it!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    public void shouldWaitForScheduledTimerToElapse() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.scheduleTimer("Sleep for 3 seconds", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED);
                    assertThat(entry.getTimerScheduled().getName()).isEqualTo("Sleep for 3 seconds");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    public void shouldWaitForMultipleScheduledTimersToElapse() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
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
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));

        assertThat(engine.getRunInbox(runId)).isEmpty();
    }

    @Test
    public void shouldWaitForSubWorkflowRun() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final Optional<String> subWorkflowResult = ctx.callSubWorkflow(
                    "bar", 1, null, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(subWorkflowResult).contains("inputValue-outputValue");
            return Optional.empty();
        });

        engine.registerWorkflowRunner("bar", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5),
                ctx -> ctx.argument().map(argument -> argument + "-outputValue"));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldFailWhenSubWorkflowRunFails() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowRunner("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Oh no!");
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_FAILED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("RuntimeException: IllegalStateException: Oh no!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldCancelSubWorkflowRunsRecursivelyWhenParentRunIsCancelled() {
        final var childRunIdReference = new AtomicReference<UUID>();
        final var grandChildRunIdReference = new AtomicReference<UUID>();

        engine.registerWorkflowRunner("parent", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callSubWorkflow("child", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowRunner("child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            childRunIdReference.set(ctx.workflowRunId());
            ctx.callSubWorkflow("grand-child", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowRunner("grand-child", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            grandChildRunIdReference.set(ctx.workflowRunId());
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
    public void shouldWaitForExternalEvent() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getRun(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(runId, "foo-123", null).join();

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXTERNAL_EVENT_RECEIVED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldFailWhenWaitingForExternalEventTimesOut() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofMillis(5)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("CancellationException: ");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldRecordSideEffectResult() {
        final var sideEffectInvocationCounter = new AtomicInteger();

        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
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
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED);
                    assertThat(entry.getSideEffectExecuted().getName()).isEqualTo("sideEffect");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldNotAllowNestedSideEffects() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect("outerSideEffect", null, voidConverter(), ignored -> {
                ctx.sideEffect("nestedSideEffect", null, voidConverter(), ignored2 -> null).await();
                return null;
            }).await();

            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("IllegalStateException: Nested side effects are not allowed");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldCallActivity() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity(
                    "abc", null, voidConverter(), stringConverter(), defaultRetryPolicy()).await().orElseThrow();
            return Optional.empty();
        });

        engine.registerActivityRunner("abc", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> Optional.of("123"));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldScheduleMultipleActivitiesConcurrently() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            final List<Awaitable<String>> awaitables = List.of(
                    ctx.callActivity("abc", "first", stringConverter(), stringConverter(), defaultRetryPolicy()),
                    ctx.callActivity("abc", "second", stringConverter(), stringConverter(), defaultRetryPolicy()));

            final String joinedResult = awaitables.stream()
                    .map(Awaitable::await)
                    .map(Optional::get)
                    .collect(Collectors.joining(", "));

            return Optional.of(joinedResult);
        });

        engine.registerActivityRunner("abc", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5),
                ctx -> Optional.of(ctx.argument().orElseThrow()));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldRetryFailingActivity() {
        final var retryPolicy = defaultRetryPolicy()
                .withMaxDelay(Duration.ofMillis(10))
                .withMaxAttempts(3);

        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callActivity(
                    "abc", null, voidConverter(), stringConverter(), retryPolicy).await().orElseThrow();
            return Optional.empty();
        });

        engine.registerActivityRunner("abc", 1, voidConverter(), stringConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldPropagateTags() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            assertThat(ctx.tags()).containsExactlyInAnyOrder("oof", "rab");
            ctx.callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowRunner("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            assertThat(ctx.tags()).containsExactlyInAnyOrder("oof", "rab");
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1)
                .withTags(Set.of("oof", "rab")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(engine.getRunJournal(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED);
                    assertThat(entry.getRunScheduled().getTagsList()).containsExactlyInAnyOrder("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED);
                    assertThat(entry.getSubWorkflowRunScheduled().getTagsList()).containsExactlyInAnyOrder("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldSupportWorkflowVersioning() {
        // TODO
    }

    private WorkflowRunRow awaitRunStatus(
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

    private WorkflowRunRow awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(5));
    }

}