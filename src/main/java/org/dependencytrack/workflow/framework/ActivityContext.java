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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.workflow.framework.persistence.model.ActivityTaskId;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Context available to {@link ActivityExecutor}s.
 *
 * @param <T> Type of the activity's argument.
 */
public final class ActivityContext<T> implements Closeable {

    private final WorkflowEngine engine;
    private final UUID workflowRunId;
    private final int scheduledEventId;
    private final T argument;
    private final ActivityExecutor<T, ?> activityExecutor;
    private final Duration lockTimeout;
    private final ScheduledExecutorService heartbeatExecutor;
    private volatile Instant lockedUntil;

    ActivityContext(
            final WorkflowEngine engine,
            final UUID workflowRunId,
            final int scheduledEventId,
            final T argument,
            final ActivityExecutor<T, ?> activityExecutor,
            final Duration lockTimeout,
            final Instant lockedUntil) {
        this.engine = engine;
        this.workflowRunId = workflowRunId;
        this.scheduledEventId = scheduledEventId;
        this.argument = argument;
        this.activityExecutor = activityExecutor;
        this.lockTimeout = lockTimeout;
        this.lockedUntil = lockedUntil;

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

    public UUID workflowRunId() {
        return workflowRunId;
    }

    public Optional<T> argument() {
        return Optional.ofNullable(argument);
    }

    private void heartbeat() {
        // TODO: Fail when task was not locked by this worker.
        // TODO: Return info about workflow run so the task can
        //  detect when run was cancelled or failed.
        this.lockedUntil = engine.heartbeatActivityTask(
                new ActivityTaskId(workflowRunId, scheduledEventId), lockTimeout);
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
