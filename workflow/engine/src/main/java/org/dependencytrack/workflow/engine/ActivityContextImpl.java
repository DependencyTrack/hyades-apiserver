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

import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.engine.persistence.model.ActivityTaskId;
import org.jspecify.annotations.Nullable;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

final class ActivityContextImpl<T> implements ActivityContext, Closeable {

    private final WorkflowEngineImpl engine;
    private final UUID workflowRunId;
    private final int createdEventId;
    private final ActivityExecutor<T, ?> activityExecutor;
    private final Duration lockTimeout;
    private @Nullable ScheduledExecutorService heartbeatExecutor;
    private volatile Instant lockedUntil;

    ActivityContextImpl(
            final WorkflowEngineImpl engine,
            final UUID workflowRunId,
            final int createdEventId,
            final ActivityExecutor<T, ?> activityExecutor,
            final Duration lockTimeout,
            final Instant lockedUntil,
            final boolean heartbeatEnabled) {
        this.engine = engine;
        this.workflowRunId = workflowRunId;
        this.createdEventId = createdEventId;
        this.activityExecutor = activityExecutor;
        this.lockTimeout = lockTimeout;
        this.lockedUntil = lockedUntil;

        if (heartbeatEnabled) {
            // Heartbeat after 2/3 of the lock timeout elapsed.
            // TODO: Signal back to the activity when heartbeat failed (Interrupt?).
            final long heartbeatIntervalMillis = lockTimeout.minus(
                    lockTimeout.dividedBy(3)).toMillis();
            this.heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(Thread.ofVirtual().factory());
            heartbeatExecutor.scheduleAtFixedRate(
                    this::heartbeat,
                    heartbeatIntervalMillis,
                    heartbeatIntervalMillis,
                    TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public UUID workflowRunId() {
        return workflowRunId;
    }

    private void heartbeat() {
        // TODO: Fail when task was not locked by this worker.
        // TODO: Return info about workflow run so the task can
        //  detect when run was canceled or failed.
        this.lockedUntil = engine.heartbeatActivityTask(
                new ActivityTaskId(workflowRunId, createdEventId), lockTimeout);
        LoggerFactory.getLogger(activityExecutor.getClass()).debug(
                "Lock extended to {}", this.lockedUntil);
    }

    @Override
    public void close() {
        if (this.heartbeatExecutor != null) {
            this.heartbeatExecutor.close();
        }
    }

}
