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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.workflow.v1alpha1.RunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.RunnerCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.RunnerStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeoutException;

final class WorkflowTaskProcessor<A, R> implements TaskProcessor<WorkflowTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowTaskProcessor.class);

    private final WorkflowEngine engine;
    private final String workflowName;
    private final WorkflowRunner<A, R> workflowRunner;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final Duration taskLockTimeout;

    public WorkflowTaskProcessor(
            final WorkflowEngine engine,
            final String workflowName,
            final WorkflowRunner<A, R> workflowRunner,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration taskLockTimeout) {
        this.engine = engine;
        this.workflowName = workflowName;
        this.workflowRunner = workflowRunner;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.taskLockTimeout = taskLockTimeout;
    }

    @Override
    public List<WorkflowTask> poll(final int limit) {
        return engine.pollWorkflowTasks(workflowName, limit, taskLockTimeout);
    }

    @Override
    public void process(final WorkflowTask task) {
        try (var ignoredMdcWorkflowRunId = MDC.putCloseable("workflowRunId", task.workflowRunId().toString());
             var ignoredMdcWorkflowName = MDC.putCloseable("workflowName", task.workflowName());
             var ignoredMdcWorkflowVersion = MDC.putCloseable("workflowVersion", String.valueOf(task.workflowVersion()));
             var ignoredMdcWorkflowPriority = MDC.putCloseable("workflowPriority", String.valueOf(task.priority()));
             var ignoredMdcWorkflowConcurrencyGroupId = MDC.putCloseable("workflowConcurrencyGroupId", String.valueOf(task.concurrencyGroupId()))) {
            processInternal(task);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to process task; Abandoning it", e);
            abandon(task);
        }
    }

    @Override
    public void abandon(final WorkflowTask task) {
        try {
            // TODO: Retry on TimeoutException
            engine.abandonWorkflowTask(task).join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for task abandonment to be acknowledged", e);
        } catch (TimeoutException e) {
            throw new RuntimeException("Timed out while waiting for task abandonment to be acknowledged", e);
        }
    }

    private void processInternal(final WorkflowTask task) {
        final var workflowRun = new WorkflowRun(
                task.workflowRunId(),
                task.workflowName(),
                task.workflowVersion(),
                task.concurrencyGroupId(),
                task.eventLog());
        if (workflowRun.status().isTerminal()) {
            LOGGER.warn("""
                    Task was scheduled despite the workflow run already being in terminal state {}. \
                    Discarding {} events in the run's inbox.""", workflowRun.status(), task.inboxEvents().size());

            // TODO: Discard the inbox events without modifying the workflow run.
            // TODO: Consider logging discarded events.
            abandon(task);
            return;
        }

        // Inject a RunnerStarted event.
        // Its timestamp will be used as deterministic "now" timestamp while processing new events.
        workflowRun.onEvent(WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunnerStarted(RunnerStarted.newBuilder().build())
                .build());

        int eventsAdded = 0;
        for (final WorkflowEvent newEvent : task.inboxEvents()) {
            workflowRun.onEvent(newEvent);
            eventsAdded++;

            // Inject a RunStarted event when encountering a RunScheduled event.
            // This is mainly to populate the run's startedAt timestamp,
            // so we can differentiate between when a run was scheduled vs.
            // when it was eventually picked up.
            if (newEvent.hasRunScheduled()) {
                workflowRun.onEvent(WorkflowEvent.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setRunStarted(RunStarted.newBuilder().build())
                        .build());
                eventsAdded++;
            }
        }

        if (eventsAdded == 0) {
            LOGGER.warn("No new events");
            return;
        }

        final var ctx = new WorkflowRunContext<>(
                task.workflowRunId(),
                task.workflowName(),
                task.workflowVersion(),
                task.priority(),
                task.tags(),
                workflowRunner,
                argumentConverter,
                resultConverter,
                workflowRun.eventLog(),
                workflowRun.inboxEvents());
        final WorkflowRunResult runResult = ctx.runWorkflow();

        workflowRun.setCustomStatus(runResult.customStatus());
        workflowRun.executeCommands(runResult.commands());
        workflowRun.onEvent(WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunnerCompleted(RunnerCompleted.newBuilder().build())
                .build());

        try {
            // TODO: Retry on TimeoutException.
            engine.completeWorkflowTask(workflowRun).join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for task completion to be acknowledged", e);
        } catch (TimeoutException e) {
            throw new RuntimeException("Timed out while waiting for task completion to be acknowledged", e);
        }
    }

}
