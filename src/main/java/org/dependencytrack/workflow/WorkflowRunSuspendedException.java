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

import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventResumeCondition;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityCompletedResumeCondition;

class WorkflowRunSuspendedException extends RuntimeException {

    private final WorkflowActivityCompletedResumeCondition activityCompletedResumeCondition;
    private final ExternalEventResumeCondition externalEventResumeCondition;

    WorkflowRunSuspendedException(final WorkflowActivityCompletedResumeCondition activityCompletedResumeCondition) {
        super();
        this.activityCompletedResumeCondition = activityCompletedResumeCondition;
        this.externalEventResumeCondition = null;
    }

    WorkflowRunSuspendedException(final ExternalEventResumeCondition externalEventResumeCondition) {
        super();
        this.externalEventResumeCondition = externalEventResumeCondition;
        this.activityCompletedResumeCondition = null;
    }

    public WorkflowActivityCompletedResumeCondition getActivityCompletedResumeCondition() {
        return activityCompletedResumeCondition;
    }

    public ExternalEventResumeCondition getExternalEventResumeCondition() {
        return externalEventResumeCondition;
    }

}
