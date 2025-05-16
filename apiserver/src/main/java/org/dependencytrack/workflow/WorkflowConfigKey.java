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

import alpine.Config;

import java.util.concurrent.TimeUnit;

public enum WorkflowConfigKey implements Config.Key {

    ENGINE_ENABLED("workflow.engine.enabled", false),
    ENGINE_DATABASE_URL("workflow.engine.database.url", null),
    ENGINE_DATABASE_USERNAME("workflow.engine.database.username", null),
    ENGINE_DATABASE_PASSWORD("workflow.engine.database.password", null),
    ENGINE_DATABASE_RUN_MIGRATIONS("workflow.engine.database.run.migrations", false),
    ENGINE_WORKFLOW_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS("workflow.engine.workflow.task.dispatcher.min.poll.interval.ms", TimeUnit.SECONDS.toMillis(1)),
    ENGINE_ACTIVITY_TASK_DISPATCHER_MIN_POLL_INTERVAL_MS("workflow.engine.activity.task.dispatcher.min.poll.interval.ms", TimeUnit.SECONDS.toMillis(1)),
    ENGINE_BUFFER_TASK_COMMAND_FLUSH_INTERVAL_MS("workflow.engine.buffer.task.command.flush.interval.ms", 100),
    ENGINE_BUFFER_TASK_COMMAND_MAX_BATCH_SIZE("workflow.engine.buffer.task.command.max.batch.size", 250),
    ENGINE_BUFFER_EXTERNAL_EVENT_FLUSH_INTERVAL_MS("workflow.engine.buffer.external.event.flush.interval.ms", TimeUnit.SECONDS.toMillis(100)),
    ENGINE_BUFFER_EXTERNAL_EVENT_MAX_BATCH_SIZE("workflow.engine.buffer.external.event.max.batch.size", 100),
    ENGINE_SCHEDULER_INITIAL_DELAY_MS("workflow.engine.scheduler.initial.delay.ms", null),
    ENGINE_SCHEDULER_POLL_INTERVAL_MS("workflow.engine.scheduler.poll.interval.ms", null),
    ENGINE_INJECT_ACTIVITY_FAULTS("workflow.engine.inject.activity.faults", false),
    ENGINE_RETENTION_DAYS("workflow.engine.retention.days", null),
    ENGINE_RETENTION_DELETION_BATCH_SIZE("workflow.engine.retention.deletion.batch.size", null),
    ENGINE_RETENTION_WORKER_INITIAL_DELAY_MS("workflow.engine.retention.worker.initial.delay.ms", null),
    ENGINE_RETENTION_WORKER_INTERVAL_MS("workflow.engine.retention.worker.interval.ms", null);

    private final String name;
    private final Object defaultValue;

    WorkflowConfigKey(final String name, final Object defaultValue) {
        this.name = name;
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyName() {
        return name;
    }

    @Override
    public Object getDefaultValue() {
        return defaultValue;
    }

}
