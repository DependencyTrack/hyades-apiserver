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
package org.dependencytrack.workflow.engine.api.request;

import org.dependencytrack.proto.workflow.payload.v1.Payload;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

public record CreateWorkflowScheduleRequest(
        String name,
        String cron,
        String workflowName,
        int workflowVersion,
        @Nullable String concurrencyGroupId,
        @Nullable Integer priority,
        @Nullable Map<String, String> labels,
        @Nullable Payload argument,
        @Nullable Duration initialDelay) {

    private static final Pattern CRON_PATTERN = Pattern.compile("((((\\d+,)+\\d+|(\\d+([/\\-])\\d+)|\\d+|\\*) ?){5,7})");

    public CreateWorkflowScheduleRequest {
        requireNonNull(name, "name must not be null");
        requireNonNull(cron, "cron must not be null");
        requireValidCron(cron);
        requireNonNull(workflowName, "workflowName must not be null");
    }

    public CreateWorkflowScheduleRequest(final String name, final String cron, final String workflowName, final int workflowVersion) {
        this(name, cron, workflowName, workflowVersion, null, null, null, null, null);
    }

    public CreateWorkflowScheduleRequest withConcurrencyGroupId(@Nullable final String concurrencyGroupId) {
        return new CreateWorkflowScheduleRequest(this.name, this.cron, this.workflowName, this.workflowVersion,
                concurrencyGroupId, this.priority, this.labels, this.argument, this.initialDelay);
    }

    public CreateWorkflowScheduleRequest withPriority(@Nullable final Integer priority) {
        return new CreateWorkflowScheduleRequest(this.name, this.cron, this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, priority, this.labels, this.argument, this.initialDelay);
    }

    public CreateWorkflowScheduleRequest withLabels(@Nullable final Map<String, String> labels) {
        return new CreateWorkflowScheduleRequest(this.name, this.cron, this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, labels, this.argument, this.initialDelay);
    }

    public CreateWorkflowScheduleRequest withArgument(@Nullable final Payload argument) {
        return new CreateWorkflowScheduleRequest(this.name, this.cron, this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, this.labels, argument, this.initialDelay);
    }

    public CreateWorkflowScheduleRequest withInitialDelay(@Nullable final Duration initialDelay) {
        return new CreateWorkflowScheduleRequest(this.name, this.cron, this.workflowName, this.workflowVersion,
                this.concurrencyGroupId, this.priority, this.labels, this.argument, initialDelay);
    }

    private static void requireValidCron(final String cron) {
        if (!CRON_PATTERN.matcher(cron).matches()) {
            throw new IllegalArgumentException("Invalid cron expression: " + cron);
        }
    }

}
