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
import org.dependencytrack.proto.workflow.v1alpha1.RunnerCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.RunnerStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.TimeoutException;

final class WorkflowRunTaskProcessor<A, R> implements WorkflowTaskProcessor<WorkflowRunTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowRunTaskProcessor.class);

    private final WorkflowEngine engine;
    private final String workflowName;
    private final WorkflowRunner<A, R> workflowRunner;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    public WorkflowRunTaskProcessor(
            final WorkflowEngine engine,
            final String workflowName,
            final WorkflowRunner<A, R> workflowRunner,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.engine = engine;
        this.workflowName = workflowName;
        this.workflowRunner = workflowRunner;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
    }

    @Override
    public List<WorkflowRunTask> poll(final int limit) {
        return engine.pollWorkflowRunTasks(workflowName, limit);
    }

    @Override
    public void process(final WorkflowRunTask task) {
        try {
            processInternal(task);
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to process task", e);
            abandon(task);
        }
    }

    @Override
    public void abandon(final WorkflowRunTask task) {
        LOGGER.debug("Abandoning task for workflow run {}", task.workflowRunId());

        try {
            // TODO: Add retry?
            engine.abandonWorkflowRunTask(task).join();
        } catch (InterruptedException | TimeoutException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void processInternal(final WorkflowRunTask task) {
        final var workflowRun = new WorkflowRun(
                task.workflowRunId(),
                task.workflowName(),
                task.workflowVersion(),
                task.eventLog());
        workflowRun.onEvent(WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunnerStarted(RunnerStarted.newBuilder().build())
                .build());

        int eventsAdded = 0;
        for (final WorkflowEvent newEvent : task.inboxEvents()) {
            workflowRun.onEvent(newEvent);
            eventsAdded++;
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
                argumentConverter.convertFromPayload(task.argument()),
                workflowRunner,
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
            // TODO: Add retry?
            engine.completeWorkflowRunTask(workflowRun).join();
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

}
