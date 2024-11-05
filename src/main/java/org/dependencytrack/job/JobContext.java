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
package org.dependencytrack.job;

import java.util.UUID;

public class JobContext<T> {

    private final Long jobId;
    private final Integer jobPriority;
    private final UUID workflowRunId;
    private final String workflowActivityName;
    private final String workflowActivityInvocationId;
    private final T arguments;

    JobContext(
            final Long jobId,
            final Integer jobPriority,
            final UUID workflowRunId,
            final String workflowActivityName,
            final String workflowActivityInvocationId,
            final T arguments) {
        this.jobId = jobId;
        this.jobPriority = jobPriority;
        this.workflowRunId = workflowRunId;
        this.workflowActivityName = workflowActivityName;
        this.workflowActivityInvocationId = workflowActivityInvocationId;
        this.arguments = arguments;
    }

    public Long jobId() {
        return jobId;
    }

    public Integer jobPriority() {
        return jobPriority;
    }

    public UUID workflowRunId() {
        return workflowRunId;
    }

    public String workflowActivityName() {
        return workflowActivityName;
    }

    public String workflowActivityInvocationId() {
        return workflowActivityInvocationId;
    }

    public T arguments() {
        return arguments;
    }

}
