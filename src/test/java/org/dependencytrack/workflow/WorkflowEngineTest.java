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
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;
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
    public void shouldFailWorkflowInstanceWhenExecutionThrows() {
        engine.registerWorkflowRunner("foo", ctx -> {
            throw new IllegalStateException("Ouch!");
        }, 1, voidConverter(), voidConverter());

        final UUID runId = engine.scheduleWorkflowRun("foo", 1);

        await("Completion")
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailureDetails()).isEqualTo("IllegalStateException: Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldWaitForScheduledTimerToElapse() {
        engine.registerWorkflowRunner("foo", ctx -> {
            ctx.scheduleTimer(Duration.ofSeconds(3)).await();
            return Optional.empty();
        }, 1, voidConverter(), voidConverter());

        final UUID runId = engine.scheduleWorkflowRun("foo", 1);

        await("Completion")
                .atMost(Duration.ofSeconds(66666))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldWaitForScheduledSubWorkflow() {
        engine.registerWorkflowRunner("foo", ctx -> {
            final Optional<String> subWorkflowResult = ctx.callSubWorkflow(
                    "bar", 1, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(subWorkflowResult).contains("inputValue-outputValue");
            return Optional.empty();
        }, 1, voidConverter(), voidConverter());

        engine.registerWorkflowRunner("bar", ctx -> ctx.argument().map(argument -> argument + "-outputValue"), 1,
                stringConverter(), stringConverter());

        final UUID runId = engine.scheduleWorkflowRun("foo", 1);

        await("Completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SUB_WORKFLOW_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldWaitForExternalEvent() {
        engine.registerWorkflowRunner("foo", ctx -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return Optional.empty();
        }, 1, voidConverter(), voidConverter());

        final UUID runId = engine.scheduleWorkflowRun("foo", 1);

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(runId, "foo-123", null);

        await("Completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXTERNAL_EVENT_RECEIVED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_COMPLETED));
    }

    @Test
    public void shouldCallActivities() {
        engine.registerWorkflowRunner("foo", ctx -> {
            ctx.callActivity("bar", null, voidConverter(), voidConverter()).await();
            return Optional.empty();
        }, 1, voidConverter(), voidConverter());

        final UUID runId = engine.scheduleWorkflowRun("foo", 1);

        await("Completion")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                });

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_SCHEDULED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_FIRED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED));
    }

    @Test
    public void shouldRecordSideEffectResult() {
        final var sideEffectInvocationCounter = new AtomicInteger();

        engine.registerWorkflowRunner("foo", ctx -> {
            ctx.sideEffect(ignored -> {
                sideEffectInvocationCounter.incrementAndGet();
                return null;
            }, null, voidConverter()).await();

            ctx.scheduleTimer(Duration.ofMillis(10)).await();
            return Optional.empty();
        }, 1, voidConverter(), voidConverter());

        final UUID runId = engine.scheduleWorkflowRun("foo", 1);

        await("Completion")
                .atMost(Duration.ofSeconds(15))
                .untilAsserted(() -> {
                    final WorkflowRunRow run = engine.getWorkflowRun(runId);
                    assertThat(run.status()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                });

        assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

        assertThat(engine.getWorkflowEventLog(runId)).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUNNER_STARTED),
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
    public void shouldSupportWorkflowVersioning() {
        // TODO
    }

}