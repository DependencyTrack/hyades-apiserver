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
package org.dependencytrack.job.event;

import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.dependencytrack.event.kafka.consumer.KafkaBatchConsumer;
import org.dependencytrack.job.JobStatus;
import org.dependencytrack.job.QueuedJob;
import org.dependencytrack.job.persistence.JobDao;
import org.dependencytrack.job.persistence.JobStatusTransition;
import org.dependencytrack.proto.job.v1alpha1.JobEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class JobEventConsumer extends KafkaBatchConsumer<Long, JobEvent> {

    private static final Set<JobEvent.SubjectCase> RELEVANT_EVENT_SUBJECTS = Set.of(
            JobEvent.SubjectCase.JOB_COMPLETED_SUBJECT,
            JobEvent.SubjectCase.JOB_FAILED_SUBJECT);

    public JobEventConsumer(
            final KafkaConsumer<Long, JobEvent> kafkaConsumer,
            final Duration batchLingerDuration,
            final int batchSize) {
        super(kafkaConsumer, batchLingerDuration, batchSize);
    }

    @Override
    protected boolean shouldAddToBatch(final ConsumerRecord<Long, JobEvent> record) {
        return RELEVANT_EVENT_SUBJECTS.contains(record.value().getSubjectCase());
    }

    @Override
    protected boolean flushBatch(final List<ConsumerRecord<Long, JobEvent>> records) {
        final var latestEventByJobId = new HashMap<Long, JobEvent>();
        for (final ConsumerRecord<Long, JobEvent> record : records) {
            final JobEvent event = record.value();

            latestEventByJobId.compute(event.getJobId(), (ignored, oldEvent) -> {
                if (oldEvent == null) {
                    return event;
                }

                final int result = Timestamps.compare(oldEvent.getTimestamp(), event.getTimestamp());
                if (result > 0) {
                    return oldEvent;
                }

                return event;
            });
        }

        final List<JobStatusTransition> transitions = latestEventByJobId.values().stream()
                .map(event -> {
                    final long eventTimestampMillis = Timestamps.toMillis(event.getTimestamp());
                    final Instant eventTimestamp = Instant.ofEpochMilli(eventTimestampMillis);

                    return switch (event.getSubjectCase()) {
                        case JOB_COMPLETED_SUBJECT -> new JobStatusTransition(
                                event.getJobId(), JobStatus.COMPLETED, eventTimestamp);
                        case JOB_FAILED_SUBJECT -> {
                            final JobEvent.JobFailedSubject jobFailedSubject = event.getJobFailedSubject();
                            final boolean isRetryable = jobFailedSubject.hasNextAttemptAt();
                            final JobStatus newStatus = isRetryable ? JobStatus.PENDING_RETRY : JobStatus.FAILED;
                            final Instant nextAttemptAt = jobFailedSubject.hasNextAttemptAt()
                                    ? Instant.ofEpochMilli(Timestamps.toMillis(jobFailedSubject.getNextAttemptAt()))
                                    : null;

                            yield new JobStatusTransition(event.getJobId(), newStatus, eventTimestamp)
                                    .withFailureReason(jobFailedSubject.getFailureReason())
                                    .withScheduledFor(nextAttemptAt);
                        }
                        default -> throw new IllegalStateException("Unexpected event: " + event);
                    };
                })
                .toList();

        useJdbiTransaction(handle -> {
            final var dao = new JobDao(handle);
            final List<QueuedJob> transitionedJobs = dao.transitionAll(transitions);

            // NB: Assertion can fail when replaying historical events,
            // or when consuming duplicate records.
            assert transitionedJobs.size() == transitions.size()
                    : "Expected to transition %d jobs, but only transitioned %d".formatted(
                    transitions.size(), transitionedJobs.size());
        });

        return true;
    }

}
