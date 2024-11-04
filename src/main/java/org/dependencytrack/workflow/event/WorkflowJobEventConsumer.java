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
package org.dependencytrack.workflow.event;

import alpine.common.logging.Logger;
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.dependencytrack.event.kafka.consumer.KafkaBatchConsumer;
import org.dependencytrack.job.JobEngine;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.dependencytrack.proto.job.v1alpha1.JobEvent;
import org.dependencytrack.workflow.ClaimedWorkflowStepRun;
import org.dependencytrack.workflow.WorkflowRun;
import org.dependencytrack.workflow.WorkflowRunStatus;
import org.dependencytrack.workflow.WorkflowRunTransition;
import org.dependencytrack.workflow.WorkflowStepRun;
import org.dependencytrack.workflow.WorkflowStepRunStatus;
import org.dependencytrack.workflow.WorkflowStepRunTransition;
import org.dependencytrack.workflow.WorkflowStepType;
import org.dependencytrack.workflow.persistence.WorkflowDao;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class WorkflowJobEventConsumer extends KafkaBatchConsumer<Long, JobEvent> {

    private static final Logger LOGGER = Logger.getLogger(WorkflowJobEventConsumer.class);
    private static final Set<JobEvent.SubjectCase> RELEVANT_EVENT_SUBJECTS = Set.of(
            JobEvent.SubjectCase.JOB_COMPLETED_SUBJECT,
            JobEvent.SubjectCase.JOB_FAILED_SUBJECT,
            JobEvent.SubjectCase.JOB_STARTED_SUBJECT);

    private final JobEngine jobEngine;

    public WorkflowJobEventConsumer(
            final KafkaConsumer<Long, JobEvent> kafkaConsumer,
            final JobEngine jobEngine,
            final Duration batchLingerDuration,
            final int batchSize) {
        super(kafkaConsumer, batchLingerDuration, batchSize);
        this.jobEngine = jobEngine;
    }

    @Override
    protected boolean shouldAddToBatch(final ConsumerRecord<Long, JobEvent> record) {
        if (!RELEVANT_EVENT_SUBJECTS.contains(record.value().getSubjectCase())) {
            return false;
        }

        if (record.value().getWorkflowStepRunId() <= 0) {
            return false;
        }

        if (record.value().getSubjectCase() == JobEvent.SubjectCase.JOB_FAILED_SUBJECT
            && (record.value().getJobFailedSubject().hasNextAttemptAt())) {
            return false;
        }

        return true;
    }

    @Override
    protected boolean flushBatch(final List<ConsumerRecord<Long, JobEvent>> records) {
        final var latestEventByStepRunId = new HashMap<Long, JobEvent>();
        for (final ConsumerRecord<Long, JobEvent> record : records) {
            final JobEvent event = record.value();

            latestEventByStepRunId.compute(event.getWorkflowStepRunId(), (ignored, oldEvent) -> {
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

        final var transitions = new ArrayList<WorkflowStepRunTransition>(latestEventByStepRunId.size());
        for (final Map.Entry<Long, JobEvent> entry : latestEventByStepRunId.entrySet()) {
            final long stepRunId = entry.getKey();
            final JobEvent event = entry.getValue();

            switch (event.getSubjectCase()) {
                case JOB_COMPLETED_SUBJECT -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId,
                        WorkflowStepRunStatus.COMPLETED,
                        /* failureReason */ null,
                        Instant.ofEpochMilli(Timestamps.toMillis(event.getTimestamp()))));
                case JOB_FAILED_SUBJECT -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId,
                        WorkflowStepRunStatus.FAILED,
                        "Job failed: %s".formatted(event.getJobFailedSubject().getFailureReason()),
                        Instant.ofEpochMilli(Timestamps.toMillis(event.getTimestamp()))));
                case JOB_STARTED_SUBJECT -> transitions.add(new WorkflowStepRunTransition(
                        stepRunId,
                        WorkflowStepRunStatus.RUNNING,
                        /* failureReason */ null,
                        Instant.ofEpochMilli(Timestamps.toMillis(event.getTimestamp()))));
                default -> throw new IllegalStateException("Unexpected event: " + event);
            }
        }

        final var jobsToQueue = new ArrayList<NewJob>();
        useJdbiTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final List<WorkflowStepRun> transitionedStepRuns = dao.transitionWorkflowStepRuns(transitions);

            // NB: Assertion can fail when replaying historical events,
            // or when consuming duplicate records.
            assert transitionedStepRuns.size() == transitions.size()
                    : "Should have transitioned %d step runs, but only did %d".formatted(
                    transitions.size(), transitionedStepRuns.size());

            LOGGER.debug("Transitioned status of %d workflow step runs".formatted(transitionedStepRuns.size()));
            final Map<WorkflowStepRunStatus, List<WorkflowStepRun>> stepRunsByStatus = transitionedStepRuns.stream()
                    .collect(Collectors.groupingBy(WorkflowStepRun::status, Collectors.toList()));

            final List<WorkflowStepRun> completedStepRuns = stepRunsByStatus.get(WorkflowStepRunStatus.COMPLETED);
            if (completedStepRuns != null) {
                final List<ClaimedWorkflowStepRun> claimedStepRuns = dao.claimRunnableStepRunsOfType(
                        completedStepRuns.stream().map(WorkflowStepRun::workflowRunId).toList(), WorkflowStepType.JOB);
                jobsToQueue.addAll(claimedStepRuns.stream()
                        .map(claimedStepRun -> new NewJob(claimedStepRun.stepName())
                                .withPriority(claimedStepRun.priority())
                                .withWorkflowStepRunId(claimedStepRun.id()))
                        .toList());

                final List<WorkflowRun> completedWorkflowRuns = dao.completeWorkflowRunsWhenAllStepRunsCompleted(
                        completedStepRuns.stream().map(WorkflowStepRun::workflowRunId).toList());
                if (LOGGER.isDebugEnabled()) {
                    for (final WorkflowRun completedWorkflowRun : completedWorkflowRuns) {
                        LOGGER.debug("Completed %s".formatted(completedWorkflowRun));
                    }
                }
            }

            final List<WorkflowStepRun> failedStepRuns = stepRunsByStatus.get(WorkflowStepRunStatus.FAILED);
            if (failedStepRuns != null) {
                final List<WorkflowStepRun> cancelledStepRuns = dao.cancelDependantWorkflowStepRuns(failedStepRuns);
                for (final WorkflowStepRun cancelledStepRun : cancelledStepRuns) {
                    LOGGER.warn("Cancelled %s".formatted(cancelledStepRun));
                }

                final List<WorkflowRun> failedWorkflowRuns = dao.transitionWorkflowRuns(failedStepRuns.stream()
                        .map(stepRun -> new WorkflowRunTransition(
                                stepRun.workflowRunId(),
                                WorkflowRunStatus.FAILED))
                        .toList());
                for (final WorkflowRun failedWorkflowRun : failedWorkflowRuns) {
                    LOGGER.warn("Failed %s".formatted(failedWorkflowRun));
                }
            }
        });

        if (!jobsToQueue.isEmpty()) {
            final List<QueuedJob> queuedJobs = jobEngine.enqueueAll(jobsToQueue);
            if (LOGGER.isDebugEnabled()) {
                for (final QueuedJob queuedJob : queuedJobs) {
                    LOGGER.debug("Queued %s".formatted(queuedJob));
                }
            }
        }

        return true;
    }

}
