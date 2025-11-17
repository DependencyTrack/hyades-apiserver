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
package org.dependencytrack.workflow.engine.api;

import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.engine.api.event.WorkflowEngineEvent;
import org.dependencytrack.workflow.engine.api.event.WorkflowEngineEventListener;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.CreateActivityTaskQueueRequest;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.engine.api.request.ListActivityTaskQueuesRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunEventsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.proto.event.v1.Event;
import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface WorkflowEngine extends Closeable {

    void start();

    WorkflowEngineHealthProbeResult probeHealth();

    /**
     * Register a workflow.
     * <p>
     * The executor's class <strong>must</strong> be annotated with {@link Workflow}.
     *
     * @param executor          The {@link WorkflowExecutor} of the workflow.
     * @param argumentConverter The {@link PayloadConverter} to use for arguments.
     * @param resultConverter   The {@link PayloadConverter} to use for results.
     * @param lockTimeout       How long runs of this workflow shall be locked for execution.
     * @param <A>               Type of the workflow's argument.
     * @param <R>               Type of the workflow's result.
     * @throws IllegalStateException When the engine was already started.
     */
    <A, R> void registerWorkflow(
            WorkflowExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout);

    /**
     * Register an activity.
     * <p>
     * The executor's class <strong>must</strong> be annotated with {@link Activity}.
     *
     * @param executor          The {@link ActivityExecutor} of the activity.
     * @param argumentConverter The {@link PayloadConverter} to use for arguments.
     * @param resultConverter   The {@link PayloadConverter} to use for results.
     * @param lockTimeout       How instances of this activity shall be locked for execution.
     * @param heartbeatEnabled  Whether the engine should send heartbeats to extend locks,
     *                          in case the activity takes longer than expected to complete.
     * @param <A>               Type of the activity's argument.
     * @param <R>               Type of the activity's result.
     * @throws IllegalStateException When the engine was already started.
     */
    <A, R> void registerActivity(
            ActivityExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout,
            boolean heartbeatEnabled);

    void registerActivityWorker(ActivityTaskWorkerOptions options);

    void registerWorkflowWorker(WorkflowTaskWorkerOptions options);

    /**
     * Add a listener for {@link WorkflowEngineEvent}s.
     *
     * @param listener The {@link WorkflowEngineEventListener} to add
     * @throws IllegalStateException When the engine was already started.
     */
    void addEventListener(WorkflowEngineEventListener<?> listener);

    /**
     * Create one or more workflow runs.
     *
     * @param requests Requests for runs to create.
     * @return IDs of the created runs.
     * @throws NoSuchElementException When a workflow is not known to the engine.
     */
    List<UUID> createRuns(Collection<CreateWorkflowRunRequest<?>> requests);

    /**
     * Creates a single workflow run.
     *
     * @param request Request for the run to create.
     * @param <A>     Type of the workflow's argument.
     * @return ID of the created run.
     * @see #createRuns(Collection)
     */
    default <A> UUID createRun(final CreateWorkflowRunRequest<A> request) {
        final List<UUID> results = createRuns(List.of(request));
        if (results.isEmpty()) {
            throw new IllegalStateException("createRuns returned no results");
        }

        return results.getFirst();
    }

    /**
     * Retrieve all data about a workflow run, including its full event history.
     * <p>
     * If only high-level information about the run is required, prefer to use
     * {@link #getRunMetadata(UUID)} as it is significantly more efficient.
     *
     * @param id ID of the workflow run.
     * @return The run data, or {@code null} if no run with the given ID exists.
     */
    @Nullable
    WorkflowRun getRun(UUID id);

    /**
     * Retrieve metadata about a workflow run.
     *
     * @param id ID of the workflow run.
     * @return The run metadata, or {@code null} if no run with the given ID exists.
     */
    @Nullable
    WorkflowRunMetadata getRunMetadata(UUID id);

    Page<WorkflowRunMetadata> listRuns(ListWorkflowRunsRequest request);

    /**
     * Request the cancellation of a workflow run.
     * <p>
     * Note that the cancellation is not instantaneous.
     * It is possible that the corresponding workflow run completes execution before the cancellation can take effect.
     *
     * @param runId  ID of the workflow run to cancel.
     * @param reason Reason for why the run is being canceled.
     * @throws NoSuchElementException When no workflow run with the given ID exists.
     * @throws IllegalStateException  When the workflow run is already in a terminal state,
     *                                or a cancellation has already been requested.
     */
    void requestRunCancellation(UUID runId, String reason);

    /**
     * Request the suspension of a workflow run.
     * <p>
     * Note that the suspension is not instantaneous.
     * It is possible that the corresponding workflow run completes execution before the suspension can take effect.
     *
     * @param runId ID of the workflow run to suspend.
     * @throws NoSuchElementException When no workflow run with the given ID exists.
     * @throws IllegalStateException  When the workflow run is already in a suspended or terminal state,
     *                                or a suspension has already been requested.
     */
    void requestRunSuspension(UUID runId);

    /**
     * Request the resumption of a currently suspended workflow run.
     * <p>
     * Note that the resumption is not instantaneous.
     * It is possible that the corresponding workflow run completes execution before the suspension can take effect.
     *
     * @param runId ID of the workflow run to cancel.
     * @throws IllegalStateException When the workflow run is <em>not</em> in a suspended state,
     *                               already in a terminal state, or a resumption has already been requested.
     */
    void requestRunResumption(UUID runId);

    /**
     * Retrieve the event history of a workflow run.
     *
     * @param request The request.
     * @return A {@link Page} containing {@link Event}s.
     */
    Page<Event> listRunEvents(ListWorkflowRunEventsRequest request);

    /**
     * Send an external event to a workflow run.
     *
     * @param externalEvent The {@link ExternalEvent} to send.
     * @return A {@link CompletableFuture} that will complete when the event was successfully
     * recorded in the recipient workflow run's message inbox.
     * @throws IllegalStateException When the engine is not running.
     */
    CompletableFuture<Void> sendExternalEvent(ExternalEvent externalEvent);

    void createActivityTaskQueue(CreateActivityTaskQueueRequest request);

    /**
     * List all activity task queues known to the engine.
     *
     * @param request The request.
     * @return A {@link Page} containing {@link ActivityTaskQueue}s.
     */
    Page<ActivityTaskQueue> listActivityTaskQueues(ListActivityTaskQueuesRequest request);

    /**
     * Pause a given activity task queue.
     *
     * @param queueName Name of the queue to pause.
     * @return {@code true} when the queue was paused, otherwise {@code false}.
     */
    boolean pauseActivityTaskQueue(String queueName);

    /**
     * Resume a given activity task queue.
     *
     * @param queueName Name of the queue to resume.
     * @return {@code true} when the queue was resumed, otherwise {@code false}.
     */
    boolean resumeActivityTaskQueue(String queueName);

}
