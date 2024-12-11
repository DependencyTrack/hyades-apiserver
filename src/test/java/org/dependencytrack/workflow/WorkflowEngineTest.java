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
package org.dependencytrack.workflow;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.persistence.model.WorkflowRunRow;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELLED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;
import static org.dependencytrack.workflow.RetryPolicy.defaultRetryPolicy;
import static org.dependencytrack.workflow.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.workflow.payload.PayloadConverters.voidConverter;

public class WorkflowEngineTest extends PersistenceCapableTest {

    private WorkflowEngine engine;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        engine = new WorkflowEngine();
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
    public void shouldFailWorkflowRunWhenExecutionThrows() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Ouch!");
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("IllegalStateException: Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldFailWorkflowRunWhenCancelled() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.scheduleTimer("sleep", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Start")
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.RUNNING);
                });

        engine.cancelWorkflowRun(runId, "Stop it!");

        await("Completion")
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.CANCELLED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("Stop it!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldWaitForScheduledTimerToElapse() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.scheduleTimer("Sleep for 3 seconds", Duration.ofSeconds(3)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED);
                    assertThat(entry.getTimerScheduled().getName()).isEqualTo("Sleep for 3 seconds");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldWaitForMultipleScheduledTimersToElapse() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final var timers = new ArrayList<Awaitable<Void>>(3);
            for (int i = 0; i < 3; i++) {
                timers.add(ctx.scheduleTimer("sleep", Duration.ofSeconds(3)));
            }

            for (final Awaitable<Void> timer : timers) {
                timer.await();
            }

            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldWaitForScheduledSubWorkflow() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            final Optional<String> subWorkflowResult = ctx.callSubWorkflow(
                    "bar", 1, null, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(subWorkflowResult).contains("inputValue-outputValue");
            return Optional.empty();
        });

        engine.registerWorkflowRunner("bar", 1, stringConverter(), stringConverter(), Duration.ofSeconds(5),
                ctx -> ctx.argument().map(argument -> argument + "-outputValue"));

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .atMost(Duration.ofSeconds(10))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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
    public void shouldFailWhenScheduledSubWorkflowFails() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.callSubWorkflow("bar", 1, null, null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        });

        engine.registerWorkflowRunner("bar", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            throw new IllegalStateException("Oh no!");
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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
    public void shouldWaitForExternalEvent() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(runId, "foo-123", null).join();

        await("Completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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

        await("Completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
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
            ctx.sideEffect(null, voidConverter(), ignored -> {
                sideEffectInvocationCounter.incrementAndGet();
                return null;
            }).await();

            ctx.scheduleTimer("sleep", Duration.ofMillis(10)).await();
            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldNotAllowNestedSideEffects() {
        engine.registerWorkflowRunner("foo", 1, voidConverter(), voidConverter(), Duration.ofSeconds(5), ctx -> {
            ctx.sideEffect(null, voidConverter(), ignored -> {
                ctx.sideEffect(null, voidConverter(), ignored2 -> null).await();
                return null;
            }).await();

            return Optional.empty();
        });

        final UUID runId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("foo", 1));

        await("Completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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

        await("Completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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

        await("Completion")
                .atMost(Duration.ofSeconds(30))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
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
    public void shouldSupportWorkflowVersioning() {
        // TODO
    }

}