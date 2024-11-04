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
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.LongDeserializer;
import org.dependencytrack.job.JobEngine;
import org.dependencytrack.job.NewJob;
import org.dependencytrack.job.QueuedJob;
import org.dependencytrack.job.event.JobEventKafkaProtobufDeserializer;
import org.dependencytrack.proto.job.v1alpha1.JobEvent;
import org.dependencytrack.workflow.WorkflowDao.NewWorkflowRun;
import org.dependencytrack.workflow.event.WorkflowJobEventConsumer;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.AUTO_OFFSET_RESET_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

// TODO: Metrics instrumentation
public class WorkflowEngine implements Closeable {

    enum State {

        CREATED(1),  // 0
        STARTING(2), // 1
        RUNNING(3),  // 2
        STOPPING(4), // 3
        STOPPED(1);  // 4

        private final Set<Integer> allowedTransitions;

        State(final Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(final State newState) {
            return allowedTransitions.contains(newState.ordinal());
        }

        private boolean isCreatedOrStopped() {
            return equals(CREATED) || equals(STOPPED);
        }

        private void assertRunning() {
            if (!equals(RUNNING)) {
                throw new IllegalStateException(
                        "Engine must be in state %s, but is %s".formatted(RUNNING, this));
            }
        }

    }

    private static final Logger LOGGER = Logger.getLogger(WorkflowEngine.class);
    private static final WorkflowEngine INSTANCE = new WorkflowEngine();

    private final UUID instanceId = UUID.randomUUID();
    private final JobEngine jobEngine;
    private volatile State state = State.CREATED;
    private final ReentrantLock stateLock = new ReentrantLock();
    private WorkflowJobEventConsumer jobEventConsumer;
    private Thread jobEventConsumerThread;
    private KafkaConsumer<Long, JobEvent> jobEventKafkaConsumer;
    private KafkaClientMetrics jobEventKafkaConsumerMetrics;

    public WorkflowEngine(final JobEngine jobEngine) {
        this.jobEngine = jobEngine;
    }

    public WorkflowEngine() {
        this(JobEngine.getInstance());
    }

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        jobEventKafkaConsumer = new KafkaConsumer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, LongDeserializer.class.getName()),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, JobEventKafkaProtobufDeserializer.class.getName()),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-workflowengine-jobeventconsumer-" + instanceId),
                Map.entry(GROUP_ID_CONFIG, "dtrack-workflowengine"),
                Map.entry(ENABLE_AUTO_COMMIT_CONFIG, "false"),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest")));
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            jobEventKafkaConsumerMetrics = new KafkaClientMetrics(jobEventKafkaConsumer);
            jobEventKafkaConsumerMetrics.bindTo(Metrics.getRegistry());
        }

        jobEventConsumer = new WorkflowJobEventConsumer(
                jobEventKafkaConsumer,
                jobEngine,
                /* batchLingerDuration */ Duration.ofMillis(500),
                /* batchSize */ 1000);
        jobEventKafkaConsumer.subscribe(List.of("dtrack.event.job"), jobEventConsumer);
        jobEventConsumerThread = new Thread(jobEventConsumer, "WorkflowEngine-JobEventConsumer");
        jobEventConsumerThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        jobEventConsumerThread.start();

        setState(State.RUNNING);
    }

    // TODO: Listeners for workflow run state change?
    // TODO: Listeners for workflow step run state change?
    // TODO: Share transaction with JobEngine?

    public void deploy(final WorkflowSpec spec) {
        // TODO: Validate spec

        useJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            LOGGER.info("Deploying workflow %s/%d".formatted(spec.name(), spec.version()));
            final Workflow workflow = dao.createWorkflow(new NewWorkflow(spec.name(), spec.version()));
            if (workflow == null) {
                throw new IllegalStateException("Workflow %s/%d is already deployed".formatted(
                        spec.name(), spec.version()));
            }

            final var workflowStepByName = new HashMap<String, WorkflowStep>(spec.stepSpecs().size());
            final var workflowStepDependencies = new HashMap<String, Set<String>>();
            for (final WorkflowStepSpec stepSpec : spec.stepSpecs()) {
                final WorkflowStep step = dao.createStep(new NewWorkflowStep(workflow.id(), stepSpec.name(), stepSpec.type()));
                workflowStepByName.put(step.name(), step);

                if (!stepSpec.stepDependencies().isEmpty()) {
                    workflowStepDependencies.put(step.name(), stepSpec.stepDependencies());
                }
            }

            for (final Map.Entry<String, Set<String>> entry : workflowStepDependencies.entrySet()) {
                final String stepName = entry.getKey();
                final Set<String> dependencyNames = entry.getValue();

                final WorkflowStep step = workflowStepByName.get(stepName);
                for (final String dependencyName : dependencyNames) {
                    final WorkflowStep dependencyStep = workflowStepByName.get(dependencyName);
                    dao.createStepDependency(step.id(), dependencyStep.id());
                }
            }
        });
    }

    public List<WorkflowRunView> startWorkflows(final Collection<StartWorkflowOptions> options) {
        requireNonNull(options);
        state.assertRunning();

        final var jobsToQueue = new ArrayList<NewJob>();
        final List<WorkflowRunView> startedWorkflowRuns = inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final Map<Long, WorkflowRun> workflowRunById = dao.createWorkflowRuns(options.stream()
                            .map(startOptions -> new NewWorkflowRun(
                                    startOptions.name(),
                                    startOptions.version(),
                                    UUID.randomUUID(),
                                    startOptions.priority(),
                                    startOptions.arguments()))
                            .toList())
                    .stream()
                    .collect(Collectors.toMap(WorkflowRun::id, Function.identity()));
            if (workflowRunById.size() != options.size()) {
                throw new IllegalStateException("Expected to start %d workflow runs, but only started %d".formatted(
                        options.size(), workflowRunById.size()));
            }

            final Map<Long, List<WorkflowStepRun>> workflowStepRunsByWorkflowRunId = dao.createWorkflowStepRuns(workflowRunById.values()).stream()
                    .collect(Collectors.groupingBy(WorkflowStepRun::workflowRunId, Collectors.toList()));

            final var workflowRunViews = new ArrayList<WorkflowRunView>(workflowRunById.size());
            for (final Map.Entry<Long, List<WorkflowStepRun>> entry : workflowStepRunsByWorkflowRunId.entrySet()) {
                final WorkflowRun workflowRun = workflowRunById.get(entry.getKey());
                final List<WorkflowStepRun> workflowStepRuns = entry.getValue();

                workflowRunViews.add(new WorkflowRunView(
                        "", // TODO: Get this.
                        1, // TODO: Get this.
                        workflowRun.token(),
                        workflowRun.priority(),
                        workflowRun.status(),
                        workflowRun.createdAt(),
                        workflowRun.updatedAt(),
                        workflowRun.startedAt()));
            }

            final List<ClaimedWorkflowStepRun> claimedStepRuns = dao.claimRunnableStepRunsOfType(
                    workflowRunById.keySet(), WorkflowStepType.JOB);
            if (!claimedStepRuns.isEmpty()) {
                jobsToQueue.addAll(claimedStepRuns.stream()
                        .map(claimedStepRun -> new NewJob(claimedStepRun.stepName())
                                .withPriority(claimedStepRun.priority())
                                .withWorkflowStepRunId(claimedStepRun.id()))
                        .toList());
            }

            return workflowRunViews;
        });

        if (!jobsToQueue.isEmpty()) {
            final List<QueuedJob> queuedJobs = jobEngine.enqueueAll(jobsToQueue);
            LOGGER.info("Queued %d jobs".formatted(queuedJobs.size()));
        }

        return startedWorkflowRuns;
    }

    public WorkflowRunView startWorkflow(final StartWorkflowOptions options) {
        final List<WorkflowRunView> startedWorkflows = startWorkflows(List.of(options));
        if (startedWorkflows.size() != 1) {
            throw new IllegalStateException("Workflow was not started");
        }

        return startedWorkflows.getFirst();
    }

    public Optional<WorkflowRunView> getWorkflowRun(final UUID token) {
        return inJdbiTransaction(handle -> {
            final var dao = handle.attach(WorkflowDao.class);

            final WorkflowRunView workflowRun = dao.getWorkflowRunViewByToken(token);
            if (workflowRun == null) {
                return Optional.empty();
            }

            final List<WorkflowStepRunView> stepRuns = dao.getStepRunViewsByToken(token);

            return Optional.of(new WorkflowRunView(
                    workflowRun.workflowName(),
                    workflowRun.workflowVersion(),
                    workflowRun.token(),
                    workflowRun.priority(),
                    workflowRun.status(),
                    workflowRun.createdAt(),
                    workflowRun.updatedAt(),
                    workflowRun.startedAt(),
                    stepRuns));
        });
    }

    @Override
    public void close() throws IOException {
        if (state.isCreatedOrStopped()) {
            return;
        }

        LOGGER.info("Stopping");
        setState(State.STOPPING);

        // TODO: Ensure the shutdown timeout is enforced across all activities,
        //  i.e. the entire process should take no more than 30sec.

        LOGGER.info("Waiting for job event consumer to stop");
        jobEventConsumer.shutdown();
        try {
            final boolean terminated = jobEventConsumerThread.join(Duration.ofSeconds(30));
            if (!terminated) {
                LOGGER.warn("Job event consumer did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        jobEventKafkaConsumer.close(Duration.ofSeconds(30));
        if (jobEventKafkaConsumerMetrics != null) {
            jobEventKafkaConsumerMetrics.close();
        }

        setState(State.STOPPED);
    }

    State state() {
        return state;
    }

    private void setState(final State newState) {
        stateLock.lock();
        try {
            if (this.state == newState) {
                return;
            }

            if (this.state.canTransitionTo(newState)) {
                this.state = newState;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from state %s to %s".formatted(this.state, newState));
        } finally {
            stateLock.unlock();
        }
    }

}
