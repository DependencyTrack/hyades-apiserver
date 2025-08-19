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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.workflow.event.v1.Event;
import org.dependencytrack.proto.workflow.event.v1.ExecutionCompleted;
import org.dependencytrack.proto.workflow.event.v1.ExecutionStarted;
import org.dependencytrack.proto.workflow.event.v1.RunStarted;
import org.dependencytrack.workflow.engine.MetadataRegistry.WorkflowMetadata;
import org.dependencytrack.workflow.engine.api.WorkflowGroup;
import org.dependencytrack.workflow.engine.persistence.command.PollWorkflowTaskCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.List;
import java.util.concurrent.TimeoutException;

final class WorkflowTaskManager implements TaskManager<WorkflowTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowTaskManager.class);

    private final WorkflowEngineImpl engine;
    private final WorkflowGroup workflowGroup;
    private final MetadataRegistry metadataRegistry;
    private final List<PollWorkflowTaskCommand> pollCommands;

    WorkflowTaskManager(
            final WorkflowEngineImpl engine,
            final WorkflowGroup workflowGroup,
            final MetadataRegistry metadataRegistry) {
        this.engine = engine;
        this.workflowGroup = workflowGroup;
        this.metadataRegistry = metadataRegistry;
        this.pollCommands = workflowGroup.workflowNames().stream()
                .map(metadataRegistry::getWorkflowMetadata)
                .map(metadata -> new PollWorkflowTaskCommand(metadata.name(), metadata.lockTimeout()))
                .toList();
    }

    @Override
    public String name() {
        return workflowGroup.name();
    }

    @Override
    public List<WorkflowTask> poll(final int limit) {
        return engine.pollWorkflowTasks(pollCommands, limit);
    }

    @Override
    public void process(final WorkflowTask task) {
        try (var ignoredMdcWorkflowRunId = MDC.putCloseable("workflowRunId", task.workflowRunId().toString());
             var ignoredMdcWorkflowName = MDC.putCloseable("workflowName", task.workflowName());
             var ignoredMdcWorkflowVersion = MDC.putCloseable("workflowVersion", String.valueOf(task.workflowVersion()))) {
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

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void processInternal(final WorkflowTask task) {
        if (!workflowGroup.workflowNames().contains(task.workflowName())) {
            throw new IllegalStateException(
                    "Received task for workflow %s which is not part of the configured workflow group %s".formatted(
                            task.workflowName(), workflowGroup.name()));
        }

        final WorkflowMetadata workflowMetadata = metadataRegistry.getWorkflowMetadata(task.workflowName());

        // Hydrate workflow run state from the history.
        final var workflowRunState = new WorkflowRunState(
                task.workflowRunId(),
                task.workflowName(),
                task.workflowVersion(),
                task.concurrencyGroupId(),
                task.history());
        if (workflowRunState.status().isTerminal()) {
            LOGGER.warn("""
                    Task was scheduled despite the workflow run already being in terminal state {}. \
                    Discarding {} events in the run's inbox.""", workflowRunState.status(), task.inbox().size());

            // TODO: Discard the inbox events without modifying the workflow run.
            // TODO: Consider logging discarded events.
            abandon(task);
            return;
        }

        // Inject an ExecutionStarted event.
        // Its timestamp will be used as deterministic "now" timestamp while processing new events.
        workflowRunState.applyEvent(
                Event.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setExecutionStarted(ExecutionStarted.getDefaultInstance())
                        .build());

        int eventsAdded = 0;
        for (final Event newEvent : task.inbox()) {
            workflowRunState.applyEvent(newEvent);
            eventsAdded++;

            // Inject a RunStarted event when encountering a RunCreated event.
            // This is mainly to populate the run's startedAt timestamp,
            // so we can differentiate between when a run was created vs.
            // when it was eventually picked up.
            if (newEvent.hasRunCreated()) {
                workflowRunState.applyEvent(
                        Event.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setRunStarted(RunStarted.getDefaultInstance())
                                .build());
                eventsAdded++;
            }
        }

        if (eventsAdded == 0) {
            LOGGER.warn("No new events");
            return;
        }

        final var ctx = new WorkflowContextImpl<>(
                task.workflowRunId(),
                task.workflowName(),
                task.workflowVersion(),
                task.priority(),
                task.labels(),
                engine.executorMetadataRegistry(),
                workflowMetadata.executor(),
                workflowMetadata.argumentConverter(),
                workflowMetadata.resultConverter(),
                workflowRunState.eventHistory(),
                workflowRunState.newEvents());
        final WorkflowRunExecutionResult executionResult = ctx.execute();

        workflowRunState.setCustomStatus(executionResult.customStatus());
        workflowRunState.processCommands(executionResult.commands());
        workflowRunState.applyEvent(
                Event.newBuilder()
                        .setId(-1)
                        .setTimestamp(Timestamps.now())
                        .setExecutionCompleted(ExecutionCompleted.getDefaultInstance())
                        .build());

        try {
            // TODO: Retry on TimeoutException.
            engine.completeWorkflowTask(workflowRunState).join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for task completion to be acknowledged", e);
        } catch (TimeoutException e) {
            throw new RuntimeException("Timed out while waiting for task completion to be acknowledged", e);
        }
    }

}
