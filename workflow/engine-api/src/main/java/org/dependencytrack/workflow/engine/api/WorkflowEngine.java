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
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.dependencytrack.workflow.api.proto.v1.WorkflowPayload;

import java.io.Closeable;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public interface WorkflowEngine extends Closeable {

    void start();

    <A, R> void register(
            WorkflowExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout);

    <A, R> void register(
            ActivityExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout);

    void mount(WorkflowGroup group);

    void mount(ActivityGroup group);

    List<UUID> createRuns(Collection<CreateWorkflowRunRequest> requests);

    default UUID createRun(final CreateWorkflowRunRequest request) {
        final List<UUID> results = createRuns(List.of(request));
        return !results.isEmpty() ? results.getFirst() : null;
    }

    void requestRunCancellation(UUID runId, String reason);

    void requestRunSuspension(UUID runId);

    void requestRunResumption(UUID runId);

    CompletableFuture<Void> sendExternalEvent(UUID runId, String eventId, WorkflowPayload payload);

    List<WorkflowSchedule> createSchedules(Collection<CreateWorkflowScheduleRequest> requests);

    // TODO: Methods to query runs.

}
