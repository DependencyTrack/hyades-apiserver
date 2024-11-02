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
package org.dependencytrack.job.persistence;

import org.dependencytrack.job.JobStatus;

import java.time.Instant;
import java.util.Objects;

public record JobStatusTransition(
        long jobId,
        JobStatus status,
        Instant timestamp,
        String failureReason,
        Instant scheduledFor) {

    public JobStatusTransition(final long jobId, final JobStatus status, final Instant timestamp) {
        this(jobId, Objects.requireNonNull(status), Objects.requireNonNull(timestamp), null, null);
    }

    public JobStatusTransition withFailureReason(final String failureReason) {
        return new JobStatusTransition(this.jobId, this.status, this.timestamp, failureReason, this.scheduledFor);
    }

    public JobStatusTransition withScheduledFor(final Instant scheduledFor) {
        return new JobStatusTransition(this.jobId, this.status, this.timestamp, this.failureReason, scheduledFor);
    }

}
