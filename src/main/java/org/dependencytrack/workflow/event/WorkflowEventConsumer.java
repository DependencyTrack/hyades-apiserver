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
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.event.kafka.consumer.KafkaBatchConsumer;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.dependencytrack.job.persistence.JobDao;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowActivityRunQueued;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowRunStarted;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowStepRunQueued;
import org.dependencytrack.workflow.persistence.NewWorkflowRunHistoryEntry;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.WorkflowRunHistoryEntryRow;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class WorkflowEventConsumer extends KafkaBatchConsumer<UUID, WorkflowEvent> {

    private static final Logger LOGGER = Logger.getLogger(WorkflowEventConsumer.class);

    private final KafkaProducer<UUID, WorkflowEvent> kafkaProducer;

    public WorkflowEventConsumer(
            final KafkaConsumer<UUID, WorkflowEvent> kafkaConsumer,
            final KafkaProducer<UUID, WorkflowEvent> kafkaProducer,
            final Duration batchLingerDuration,
            final int batchSize) {
        super(kafkaConsumer, batchLingerDuration, batchSize);
        this.kafkaProducer = kafkaProducer;
    }

    @Override
    protected boolean flushBatch(final List<ConsumerRecord<UUID, WorkflowEvent>> records) {
        final Map<UUID, List<WorkflowEvent>> eventsByWorkflowRunId = records.stream()
                .collect(Collectors.groupingBy(
                        ConsumerRecord::key, Collectors.mapping(
                                ConsumerRecord::value, Collectors.toList())));

        // Prepare history entries for all events in this batch.
        final var newHistoryEntries = new ArrayList<NewWorkflowRunHistoryEntry>(records.size());
        for (final Map.Entry<UUID, List<WorkflowEvent>> entry : eventsByWorkflowRunId.entrySet()) {
            final UUID workflowRunId = entry.getKey();
            final List<WorkflowEvent> workflowEvents = entry.getValue();

            for (final WorkflowEvent event : workflowEvents) {
                final Instant eventTimestamp = Instant.ofEpochMilli(Timestamps.toMillis(event.getTimestamp()));
                final NewWorkflowRunHistoryEntry newEntry = switch (event.getSubjectCase()) {
                    case WORKFLOW_RUN_REQUESTED -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            /* activityName */ null,
                            /* activityInvocationId */ null,
                            event.getWorkflowRunRequested().hasArguments()
                                    ? event.getWorkflowRunRequested().getArguments()
                                    : null,
                            /* result */ null);
                    case WORKFLOW_RUN_STARTED -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            /* activityName */ null,
                            /* activityInvocationId */ null,
                            event.getWorkflowRunStarted().hasArguments()
                                    ? event.getWorkflowRunStarted().getArguments()
                                    : null,
                            /* result */ null);
                    case WORKFLOW_ACTIVITY_RUN_QUEUED -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            event.getWorkflowActivityRunQueued().getActivityName(),
                            event.getWorkflowActivityRunQueued().getInvocationId(),
                            event.getWorkflowActivityRunQueued().hasArguments()
                                    ? event.getWorkflowActivityRunQueued().getArguments()
                                    : null,
                            /* result */ null);
                    case WORKFLOW_ACTIVITY_RUN_STARTED -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            event.getWorkflowActivityRunStarted().getActivityName(),
                            event.getWorkflowActivityRunStarted().getInvocationId(),
                            /* arguments */ null,
                            /* result */ null);
                    case WORKFLOW_ACTIVITY_RUN_COMPLETED -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            event.getWorkflowActivityRunCompleted().getActivityName(),
                            event.getWorkflowActivityRunCompleted().getInvocationId(),
                            /* arguments */ null,
                            event.getWorkflowActivityRunCompleted().hasResult()
                                    ? event.getWorkflowActivityRunCompleted().getResult()
                                    : null);
                    case WORKFLOW_ACTIVITY_RUN_FAILED -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            event.getWorkflowActivityRunFailed().getActivityName(),
                            event.getWorkflowActivityRunFailed().getInvocationId(),
                            /* arguments */ null,
                            JsonNodeFactory.instance.objectNode()
                                    .put("failureReason", event.getWorkflowActivityRunFailed().getFailureReason())
                                    .toString());
                    default -> new NewWorkflowRunHistoryEntry(
                            workflowRunId,
                            eventTimestamp,
                            event.getSubjectCase().name(),
                            /* activityName */ null,
                            /* activityInvocationId */ null,
                            /* arguments */ null,
                            /* result */ null);
                };

                newHistoryEntries.add(newEntry);
            }
        }

        final Map<UUID, WorkflowEvent> latestEventByRunId = eventsByWorkflowRunId.entrySet().stream()
                .map(entry -> {
                    final UUID runId = entry.getKey();
                    final List<WorkflowEvent> runEvents = entry.getValue();

                    final WorkflowEvent latestEvent = runEvents.stream()
                            .max(Comparator.comparing(WorkflowEvent::getTimestamp, Timestamps::compare))
                            .orElseThrow();
                    return Map.entry(runId, latestEvent);
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        final var recordsToSend = new ArrayList<ProducerRecord<UUID, WorkflowEvent>>();
        final var jobsToQueue = new ArrayList<NewJob>();

        for (final Map.Entry<UUID, WorkflowEvent> entry : latestEventByRunId.entrySet()) {
            final UUID runId = entry.getKey();
            final WorkflowEvent event = entry.getValue();

            switch (event.getSubjectCase()) {
                case WORKFLOW_RUN_REQUESTED -> {
                    final String workflowName = event.getWorkflowRunRequested().getName();
                    LOGGER.info("Requested run of workflow %s with ID %s".formatted(workflowName, runId));

                    jobsToQueue.add(new NewJob("workflow-" + workflowName)
                            .withWorkflowRunId(runId)
                            .withArguments(event.getWorkflowRunRequested().hasArguments()
                                    ? event.getWorkflowRunRequested().getArguments()
                                    : null));
                    final WorkflowRunStarted.Builder runStartedBuilder =
                            WorkflowRunStarted.newBuilder()
                                    .setName(workflowName);
                    if (event.getWorkflowRunRequested().hasArguments()) {
                        runStartedBuilder.setArguments(event.getWorkflowRunRequested().getArguments());
                    }
                    recordsToSend.add(new ProducerRecord<>(
                            "dtrack.event.workflow",
                            runId,
                            WorkflowEvent.newBuilder()
                                    .setWorkflowRunId(runId.toString())
                                    .setTimestamp(Timestamps.now())
                                    .setWorkflowRunStarted(runStartedBuilder.build())
                                    .build()));
                    recordsToSend.add(new ProducerRecord<>(
                            "dtrack.event.workflow",
                            runId,
                            WorkflowEvent.newBuilder()
                                    .setWorkflowRunId(runId.toString())
                                    .setTimestamp(Timestamps.now())
                                    .setWorkflowStepRunQueued(WorkflowStepRunQueued.newBuilder()
                                            .build())
                                    .build()));
                }
                case WORKFLOW_ACTIVITY_RUN_REQUESTED -> {
                    final String activityName = event.getWorkflowActivityRunRequested().getActivityName();
                    final String activityInvocationId = event.getWorkflowActivityRunRequested().getInvocationId();
                    LOGGER.info("Requested run of activity invocation %s#%s for workflow run %s".formatted(
                            activityName, activityInvocationId, runId));

                    final WorkflowActivityRunQueued.Builder subjectBuilder = WorkflowActivityRunQueued.newBuilder()
                            .setActivityName(event.getWorkflowActivityRunRequested().getActivityName())
                            .setInvocationId(event.getWorkflowActivityRunRequested().getInvocationId());
                    if (event.getWorkflowActivityRunRequested().hasArguments()) {
                        subjectBuilder.setArguments(event.getWorkflowActivityRunRequested().getArguments());
                    }

                    jobsToQueue.add(new NewJob("workflow-activity-" + activityName)
                            .withWorkflowRunId(runId)
                            .withWorkflowActivityName(activityName)
                            .withWorkflowActivityInvocationId(activityInvocationId));
                    recordsToSend.add(new ProducerRecord<>(
                            "dtrack.event.workflow",
                            runId,
                            WorkflowEvent.newBuilder()
                                    .setWorkflowRunId(runId.toString())
                                    .setTimestamp(Timestamps.now())
                                    .setWorkflowActivityRunQueued(subjectBuilder.build())
                                    .build()));
                }
            }
        }

        useJdbiTransaction(handle -> {
            final var workflowDao = new WorkflowDao(handle);
            final var jobDao = new JobDao(handle);

            final List<WorkflowRunHistoryEntryRow> createdHistoryEntries =
                    workflowDao.createWorkflowRunHistoryEntries(newHistoryEntries);
            assert createdHistoryEntries.size() == newHistoryEntries.size();

            final List<QueuedJob> queuedJobs = jobDao.enqueueAll(jobsToQueue);
            assert queuedJobs.size() == jobsToQueue.size();
        });

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
