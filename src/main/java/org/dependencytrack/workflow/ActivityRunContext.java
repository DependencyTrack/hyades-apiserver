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

import org.dependencytrack.workflow.persistence.model.ActivityTaskId;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public final class ActivityRunContext<T> {

    private final WorkflowEngine engine;
    private final UUID workflowRunId;
    private final int scheduledEventId;
    private final T argument;
    private final ActivityRunner<T, ?> activityRunner;
    private Instant lockedUntil;

    ActivityRunContext(
            final WorkflowEngine engine,
            final UUID workflowRunId,
            final int scheduledEventId,
            final T argument,
            final ActivityRunner<T, ?> activityRunner,
            final Instant lockedUntil) {
        this.engine = engine;
        this.workflowRunId = workflowRunId;
        this.scheduledEventId = scheduledEventId;
        this.argument = argument;
        this.activityRunner = activityRunner;
        this.lockedUntil = lockedUntil;
    }

    public UUID workflowRunId() {
        return workflowRunId;
    }

    public Optional<T> argument() {
        return Optional.ofNullable(argument);
    }

    public Instant lockedUntil() {
        return lockedUntil;
    }

    public void heartbeat() {
        // TODO: Fail when task was not locked by this worker.
        // TODO: Return info about workflow run so the task can
        //  detect when run was cancelled or failed.
        this.lockedUntil = engine.heartbeatActivityTask(
                new ActivityTaskId(workflowRunId, scheduledEventId));
        LoggerFactory.getLogger(activityRunner.getClass()).debug(
                "Lock extended to {}", this.lockedUntil);
    }

}
