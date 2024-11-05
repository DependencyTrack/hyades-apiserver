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
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.consumer.KafkaBatchConsumer;
import org.dependencytrack.proto.job.v1alpha1.JobEvent;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowActivityRunStarted;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowStepRunCompleted;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowStepRunFailed;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowStepRunStarted;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class WorkflowJobEventConsumer extends KafkaBatchConsumer<Long, JobEvent> {

    private static final Logger LOGGER = Logger.getLogger(WorkflowJobEventConsumer.class);
    private static final Set<JobEvent.SubjectCase> RELEVANT_EVENT_SUBJECTS = Set.of(
            JobEvent.SubjectCase.JOB_COMPLETED_SUBJECT,
            JobEvent.SubjectCase.JOB_FAILED_SUBJECT,
            JobEvent.SubjectCase.JOB_STARTED_SUBJECT);

    private final KafkaProducer<UUID, WorkflowEvent> kafkaProducer;

    public WorkflowJobEventConsumer(
            final KafkaConsumer<Long, JobEvent> kafkaConsumer,
            final KafkaProducer<UUID, WorkflowEvent> kafkaProducer,
            final Duration batchLingerDuration,
            final int batchSize) {
        super(kafkaConsumer, batchLingerDuration, batchSize);
        this.kafkaProducer = kafkaProducer;
    }

    @Override
    protected boolean shouldAddToBatch(final ConsumerRecord<Long, JobEvent> record) {
        if (!RELEVANT_EVENT_SUBJECTS.contains(record.value().getSubjectCase())) {
            return false;
        }

        if (!record.value().hasWorkflowRunId()) {
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
        final var recordsToSend = new ArrayList<ProducerRecord<UUID, WorkflowEvent>>();
        for (final ConsumerRecord<Long, JobEvent> record : records) {
            final JobEvent event = record.value();
            final String workflowRunId = event.getWorkflowRunId();
            final String activityName = event.getWorkflowActivityName();
            final String activityInvocationId = event.getWorkflowActivityInvocationId();

            switch (event.getSubjectCase()) {
                case JOB_COMPLETED_SUBJECT -> {
                    if (event.hasWorkflowActivityName()) {
                        LOGGER.info("Job for activity invocation %s#%s of workflow %s completed".formatted(
                                activityName, activityInvocationId, workflowRunId));
                        final WorkflowActivityRunCompleted.Builder activityRunCompletedBuilder =
                                WorkflowActivityRunCompleted.newBuilder()
                                        .setActivityName(event.getWorkflowActivityName())
                                        .setInvocationId(event.getWorkflowActivityInvocationId());
                        if (event.getJobCompletedSubject().hasResult()) {
                            activityRunCompletedBuilder
                                    .setResult(event.getJobCompletedSubject().getResult());
                        }
                        recordsToSend.add(new ProducerRecord<>(
                                "dtrack.event.workflow",
                                UUID.fromString(event.getWorkflowRunId()),
                                WorkflowEvent.newBuilder()
                                        .setWorkflowRunId(workflowRunId)
                                        .setTimestamp(event.getTimestamp())
                                        .setWorkflowActivityRunCompleted(activityRunCompletedBuilder.build())
                                        .build()));
                    } else {
                        LOGGER.info("Job for workflow run %s completed".formatted(workflowRunId));
                        recordsToSend.add(new ProducerRecord<>(
                                "dtrack.event.workflow",
                                UUID.fromString(event.getWorkflowRunId()),
                                WorkflowEvent.newBuilder()
                                        .setWorkflowRunId(event.getWorkflowRunId())
                                        .setTimestamp(event.getTimestamp())
                                        .setWorkflowStepRunCompleted(WorkflowStepRunCompleted.newBuilder()
                                                .build())
                                        .build()));
                    }
                }
                case JOB_FAILED_SUBJECT -> {
                    if (event.hasWorkflowActivityName()) {
                        LOGGER.info("Job for activity invocation %s#%s of workflow %s failed".formatted(
                                activityName, activityInvocationId, workflowRunId));
                        recordsToSend.add(new ProducerRecord<>(
                                "dtrack.event.workflow",
                                UUID.fromString(event.getWorkflowRunId()),
                                WorkflowEvent.newBuilder()
                                        .setWorkflowRunId(event.getWorkflowRunId())
                                        .setTimestamp(event.getTimestamp())
                                        .setWorkflowActivityRunFailed(WorkflowActivityRunFailed.newBuilder()
                                                .setFailureReason(event.getJobFailedSubject().getFailureReason())
                                                .build())
                                        .build()));
                    } else {
                        LOGGER.info("Job for workflow run %s failed".formatted(workflowRunId));
                        recordsToSend.add(new ProducerRecord<>(
                                "dtrack.event.workflow",
                                UUID.fromString(event.getWorkflowRunId()),
                                WorkflowEvent.newBuilder()
                                        .setWorkflowRunId(event.getWorkflowRunId())
                                        .setTimestamp(event.getTimestamp())
                                        .setWorkflowStepRunFailed(WorkflowStepRunFailed.newBuilder()
                                                .setFailureReason(event.getJobFailedSubject().getFailureReason())
                                                .build())
                                        .build()));
                    }
                }
                case JOB_STARTED_SUBJECT -> {
                    if (event.hasWorkflowActivityName()) {
                        LOGGER.info("Job for activity invocation %s#%s of workflow %s started".formatted(
                                activityName, activityInvocationId, workflowRunId));
                        recordsToSend.add(new ProducerRecord<>(
                                "dtrack.event.workflow",
                                UUID.fromString(event.getWorkflowRunId()),
                                WorkflowEvent.newBuilder()
                                        .setWorkflowRunId(event.getWorkflowRunId())
                                        .setTimestamp(event.getTimestamp())
                                        .setWorkflowActivityRunStarted(WorkflowActivityRunStarted.newBuilder()
                                                .build())
                                        .build()));
                    } else {
                        LOGGER.info("Job for workflow run %s started".formatted(workflowRunId));
                        recordsToSend.add(new ProducerRecord<>(
                                "dtrack.event.workflow",
                                UUID.fromString(event.getWorkflowRunId()),
                                WorkflowEvent.newBuilder()
                                        .setWorkflowRunId(event.getWorkflowRunId())
                                        .setTimestamp(event.getTimestamp())
                                        .setWorkflowStepRunStarted(WorkflowStepRunStarted.newBuilder()
                                                .build())
                                        .build()));
                    }
                }
                default -> throw new IllegalStateException("Unexpected event: " + event);
            }
        }

        final var futures = new ArrayList<CompletableFuture<?>>(recordsToSend.size());
        for (final ProducerRecord<UUID, WorkflowEvent> record : recordsToSend) {
            final var future = new CompletableFuture<>();
            futures.add(future);
            kafkaProducer.send(record, (metadata, exception) -> {
                if (exception != null) {
                    future.completeExceptionally(exception);
                } else {
                    future.complete(record);
                }
            });
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture<?>[0])).join();

        return true;
    }

}
