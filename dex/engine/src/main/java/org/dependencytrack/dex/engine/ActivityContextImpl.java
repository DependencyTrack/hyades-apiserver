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
package org.dependencytrack.dex.engine;

import org.dependencytrack.dex.api.ActivityContext;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

final class ActivityContextImpl implements ActivityContext {

    private final DexEngineImpl engine;
    private final ActivityTask task;
    private final Duration lockTimeout;

    ActivityContextImpl(
            final DexEngineImpl engine,
            final ActivityTask task,
            final Duration lockTimeout) {
        this.engine = engine;
        this.task = task;
        this.lockTimeout = lockTimeout;
    }

    @Override
    public UUID workflowRunId() {
        return task.id().workflowRunId();
    }

    @Override
    public boolean maybeHeartbeat() {
        // Debounce heartbeats such that they're only emitted if the current
        // lock is almost expired. "Almost" in this case referring to 1/3 of
        // or less of the lock timeout remaining.
        final Instant now = Instant.now();
        final Instant threshold = task.lock().expiresAt().minus(lockTimeout.dividedBy(3));
        if (now.isBefore(threshold)) {
            return false;
        }

        task.setLock(engine.heartbeatActivityTask(task.id(), task.lock(), lockTimeout).join());
        return true;
    }

}
