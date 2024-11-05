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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.google.protobuf.util.Timestamps;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.serialization.LongDeserializer;
import org.apache.kafka.common.serialization.UUIDDeserializer;
import org.apache.kafka.common.serialization.UUIDSerializer;
import org.dependencytrack.job.event.serialization.JobEventKafkaProtobufDeserializer;
import org.dependencytrack.proto.job.v1alpha1.JobEvent;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowActivityRunRequested;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.event.v1alpha1.WorkflowRunRequested;
import org.dependencytrack.workflow.event.WorkflowEventConsumer;
import org.dependencytrack.workflow.event.WorkflowJobEventConsumer;
import org.dependencytrack.workflow.event.serialization.WorkflowEventKafkaProtobufDeserializer;
import org.dependencytrack.workflow.event.serialization.WorkflowEventKafkaProtobufSerializer;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.WorkflowRunHistoryEntryRow;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.locks.ReentrantLock;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.AUTO_OFFSET_RESET_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.CLIENT_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ACKS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.COMPRESSION_TYPE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.LINGER_MS_CONFIG;
import static org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

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
    private volatile State state = State.CREATED;
    private final ReentrantLock stateLock = new ReentrantLock();
    private WorkflowEventConsumer workflowEventConsumer;
    private WorkflowJobEventConsumer jobEventConsumer;
    private Thread workflowEventConsumerThread;
    private Thread jobEventConsumerThread;
    private KafkaConsumer<UUID, WorkflowEvent> workflowEventKafkaConsumer;
    private KafkaProducer<UUID, WorkflowEvent> workflowEventKafkaProducer;
    private KafkaConsumer<Long, JobEvent> jobEventKafkaConsumer;
    private KafkaClientMetrics workflowEventKafkaConsumerMetrics;
    private KafkaClientMetrics workflowEventKafkaProducerMetrics;
    private KafkaClientMetrics jobEventKafkaConsumerMetrics;
    private WorkflowActivityResultFutureCompleter futureResolver;
    private Thread futureResolverThread;

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        workflowEventKafkaConsumer = new KafkaConsumer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, UUIDDeserializer.class.getName()),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, WorkflowEventKafkaProtobufDeserializer.class.getName()),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-workflowengine-workfloweventconsumer-" + instanceId),
                Map.entry(GROUP_ID_CONFIG, "dtrack-workflowengine"),
                Map.entry(ENABLE_AUTO_COMMIT_CONFIG, "false"),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest")));
        workflowEventKafkaProducer = new KafkaProducer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-workflowengine-workfloweventproducer-" + instanceId),
                Map.entry(KEY_SERIALIZER_CLASS_CONFIG, UUIDSerializer.class.getName()),
                Map.entry(VALUE_SERIALIZER_CLASS_CONFIG, WorkflowEventKafkaProtobufSerializer.class.getName()),
                Map.entry(COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name),
                Map.entry(LINGER_MS_CONFIG, "100"),
                Map.entry(ENABLE_IDEMPOTENCE_CONFIG, "true"),
                Map.entry(ACKS_CONFIG, "all")));
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            workflowEventKafkaConsumerMetrics = new KafkaClientMetrics(workflowEventKafkaConsumer);
            workflowEventKafkaConsumerMetrics.bindTo(Metrics.getRegistry());
            workflowEventKafkaProducerMetrics = new KafkaClientMetrics(workflowEventKafkaProducer);
            workflowEventKafkaProducerMetrics.bindTo(Metrics.getRegistry());
        }

        workflowEventConsumer = new WorkflowEventConsumer(
                workflowEventKafkaConsumer,
                workflowEventKafkaProducer,
                /* batchLingerDuration */ Duration.ofMillis(500),
                /* batchSize */ 1000);
        workflowEventKafkaConsumer.subscribe(List.of("dtrack.event.workflow"), workflowEventConsumer);
        workflowEventConsumerThread = new Thread(workflowEventConsumer, "WorkflowEngine-WorkflowEventConsumer");
        workflowEventConsumerThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        workflowEventConsumerThread.start();

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
                workflowEventKafkaProducer,
                /* batchLingerDuration */ Duration.ofMillis(500),
                /* batchSize */ 1000);
        jobEventKafkaConsumer.subscribe(List.of("dtrack.event.job"), jobEventConsumer);
        jobEventConsumerThread = new Thread(jobEventConsumer, "WorkflowEngine-JobEventConsumer");
        jobEventConsumerThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        jobEventConsumerThread.start();

        futureResolver = new WorkflowActivityResultFutureCompleter();
        futureResolverThread = new Thread(futureResolver, "WorkflowEngine-FutureResolver");
        futureResolverThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        futureResolverThread.start();

        setState(State.RUNNING);
    }

    // TODO: Listeners for workflow run state change?
    // TODO: Listeners for workflow step run state change?
    // TODO: Share transaction with JobEngine?

    public <T> UUID startWorkflow(final StartWorkflowOptions<T> options) {
        final UUID runId = UUID.randomUUID();

        final WorkflowRunRequested.Builder runRequestedBuilder =
                WorkflowRunRequested.newBuilder()
                        .setName(options.name());
        if (options.arguments() != null) {
            final String argumentsJson;
            try {
                argumentsJson = new JsonMapper().writeValueAsString(options.arguments());
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            runRequestedBuilder.setArguments(argumentsJson);
        }

        workflowEventKafkaProducer.send(new ProducerRecord<>(
                "dtrack.event.workflow",
                runId,
                WorkflowEvent.newBuilder()
                        .setWorkflowRunId(runId.toString())
                        .setTimestamp(Timestamps.now())
                        .setWorkflowRunRequested(runRequestedBuilder.build())
                        .build()));
        return runId;
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

        LOGGER.info("Waiting for workflow event consumer to stop");
        workflowEventConsumer.shutdown();
        try {
            final boolean terminated = workflowEventConsumerThread.join(Duration.ofSeconds(30));
            if (!terminated) {
                LOGGER.warn("Workflow event consumer did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
        workflowEventKafkaConsumer.close(Duration.ofSeconds(30));
        if (workflowEventKafkaConsumerMetrics != null) {
            workflowEventKafkaConsumerMetrics.close();
        }
        workflowEventKafkaProducer.close(Duration.ofSeconds(30));
        if (workflowEventKafkaProducerMetrics != null) {
            workflowEventKafkaProducerMetrics.close();
        }

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

        futureResolverThread.interrupt();

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

    public List<WorkflowRunHistoryEntryRow> getWorkflowRunHistory(final UUID workflowRunId) {
        return withJdbiHandle(handle -> new WorkflowDao(handle).getWorkflowRunHistory(workflowRunId));
    }

    public <T> WorkflowRunContext<T> getRunContext(final UUID workflowRunId) {
        return new WorkflowRunContext<>(this, workflowRunId, getWorkflowRunHistory(workflowRunId));
    }

    CompletableFuture<String> callActivity(
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final String arguments) {
        final var activityRunQueuedFuture = new CompletableFuture<RecordMetadata>();

        // TODO: If there is a pending execution already in the history,
        //  don't request a new one. Register a future for its result instead.

        final WorkflowActivityRunRequested.Builder activityRunRequestedBuilder =
                WorkflowActivityRunRequested.newBuilder()
                        .setActivityName(activityName)
                        .setInvocationId(invocationId);
        if (arguments != null) {
            activityRunRequestedBuilder.setArguments(arguments);
        }
        workflowEventKafkaProducer.send(new ProducerRecord<>(
                        "dtrack.event.workflow",
                        workflowRunId,
                        WorkflowEvent.newBuilder()
                                .setTimestamp(Timestamps.now())
                                .setWorkflowRunId(workflowRunId.toString())
                                .setWorkflowActivityRunRequested(activityRunRequestedBuilder.build())
                                .build()),
                (metadata, exception) -> {
                    if (exception != null) {
                        activityRunQueuedFuture.completeExceptionally(exception);
                    } else {
                        activityRunQueuedFuture.complete(metadata);
                    }
                });

        try {
            activityRunQueuedFuture.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }

        final var activityResultFuture = new CompletableFuture<String>();
        futureResolver.watchFuture(workflowRunId, activityName, invocationId, activityResultFuture);
        return activityResultFuture;
    }

}
