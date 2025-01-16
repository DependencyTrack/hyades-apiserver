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

import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;

import java.time.Instant;
import java.util.UUID;

/**
 * Unit of work for the execution of an activity.
 *
 * @param workflowRunId    ID of the workflow run the activity belongs to.
 * @param scheduledEventId ID of the event that scheduled the activity execution.
 * @param activityName     Name of the activity.
 * @param argument         Argument of the activity.
 * @param lockedUntil      Timestamp until when the activity is locked for execution.
 */
record ActivityTask(
        UUID workflowRunId,
        int scheduledEventId,
        String activityName,
        WorkflowPayload argument,
        Instant lockedUntil) implements Task {
}
