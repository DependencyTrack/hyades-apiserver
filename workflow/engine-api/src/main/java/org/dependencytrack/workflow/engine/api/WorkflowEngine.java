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

import org.dependencytrack.proto.workflow.api.v1.WorkflowEvent;
import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.engine.api.event.WorkflowEngineEvent;
import org.dependencytrack.workflow.engine.api.event.WorkflowEngineEventListener;
import org.dependencytrack.workflow.engine.api.pagination.Page;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowScheduleRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.workflow.engine.api.request.ListWorkflowSchedulesRequest;
import org.jspecify.annotations.Nullable;

import java.io.Closeable;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.SortedMap;
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
     * @param <A>               Type of the activity's argument.
     * @param <R>               Type of the activity's result.
     * @throws IllegalStateException When the engine was already started.
     */
    <A, R> void registerActivity(
            ActivityExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout);

    /**
     * Mount a {@link WorkflowGroup}.
     * <p>
     * All workflows in the provided group <strong>must</strong> have been registered with the engine before.
     *
     * @param group The {@link WorkflowGroup} to mount.
     * @throws IllegalStateException When any of the workflows within the group have not been registered,
     *                               or another group with the same name is already mounted.
     * @throws IllegalStateException When the engine was already started.
     * @see #registerWorkflow(WorkflowExecutor, PayloadConverter, PayloadConverter, Duration)
     */
    void mountWorkflows(WorkflowGroup group);

    /**
     * Mount an {@link ActivityGroup}.
     * <p>
     * All activities in the provided group <strong>must</strong> have been registered with the engine before.
     *
     * @param group The {@link ActivityGroup} to mount.
     * @throws IllegalStateException When any of the activities within the group have not been registered,
     *                               or another group with the same name is already mounted.
     * @throws IllegalStateException When the engine was already started.
     * @see #registerActivity(ActivityExecutor, PayloadConverter, PayloadConverter, Duration)
     */
    void mountActivities(ActivityGroup group);

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
     * @see #createRuns(Collection)
     */
    default <A> UUID createRun(final CreateWorkflowRunRequest<A> request) {
        final List<UUID> results = createRuns(List.of(request));
        if (results.isEmpty()) {
            throw new IllegalStateException("createRuns returned no results");
        }

        return results.getFirst();
    }

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
     * @return A {@link SortedMap}, where the key is the sequence number of the {@link WorkflowEvent}
     * in the workflow run's history, and the value is the {@link WorkflowEvent} itself.
     */
    Page<WorkflowEvent> listRunHistory(ListWorkflowRunHistoryRequest request);

    /**
     * Send an external event to a workflow run.
     *
     * @param runId   ID of the workflow run that shall receive the event.
     * @param eventId ID of the event that the workflow run may use for correlation.
     * @param payload Payload of the event.
     * @return A {@link CompletableFuture} that will complete when the event was successfully
     * recorded in the recipient workflow run's message inbox.
     * @throws IllegalStateException When the engine is not running.
     */
    CompletableFuture<Void> sendExternalEvent(UUID runId, String eventId, @Nullable WorkflowPayload payload);

    List<WorkflowSchedule> createSchedules(Collection<CreateWorkflowScheduleRequest> requests);

    default WorkflowSchedule createSchedule(final CreateWorkflowScheduleRequest request) {
        final List<WorkflowSchedule> results = createSchedules(List.of(request));
        if (results.isEmpty()) {
            throw new IllegalStateException("createSchedules returned no results");
        }

        return results.getFirst();
    }

    Page<WorkflowSchedule> listSchedules(ListWorkflowSchedulesRequest request);

}
