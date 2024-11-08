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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.serialization.UUIDDeserializer;
import org.apache.kafka.common.serialization.UUIDSerializer;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityCompletedResumeCondition;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunResumed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunSuspended;
import org.dependencytrack.workflow.WorkflowActivityResultCompleter.ActivityResultWatch;
import org.dependencytrack.workflow.model.StartWorkflowOptions;
import org.dependencytrack.workflow.model.WorkflowRun;
import org.dependencytrack.workflow.model.WorkflowTaskStatus;
import org.dependencytrack.workflow.persistence.NewWorkflowRun;
import org.dependencytrack.workflow.persistence.PolledWorkflowTaskRow;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.WorkflowRunLogEntryRow;
import org.dependencytrack.workflow.persistence.WorkflowRunRow;
import org.dependencytrack.workflow.serialization.WorkflowEventKafkaProtobufDeserializer;
import org.dependencytrack.workflow.serialization.WorkflowEventKafkaProtobufSerializer;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

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
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

// TODO: Metrics instrumentation
public final class WorkflowEngine implements Closeable {

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

        boolean isNotStoppingOrStopped() {
            return !equals(STOPPING) && !equals(STOPPED);
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
    final JsonMapper jsonMapper = new JsonMapper();
    private WorkflowEventConsumer eventConsumer;
    private Thread eventConsumerThread;
    private KafkaConsumer<UUID, WorkflowEvent> eventKafkaConsumer;
    private KafkaProducer<UUID, WorkflowEvent> eventKafkaProducer;
    private KafkaClientMetrics eventKafkaConsumerMetrics;
    private KafkaClientMetrics eventKafkaProducerMetrics;
    private WorkflowActivityResultCompleter activityResultCompleter;
    private Thread activityResultCompleterThread;
    private WorkflowScheduler scheduler;
    private ScheduledExecutorService schedulerExecutor;
    private final Map<String, ExecutorService> taskExecutorByQueue = new HashMap<>();
    private final IntervalFunction taskRetryIntervalFunction =
            IntervalFunction.ofExponentialRandomBackoff(1_000, 1.5, 0.3, 30_000);

    public static WorkflowEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        eventKafkaConsumer = new KafkaConsumer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, UUIDDeserializer.class.getName()),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, WorkflowEventKafkaProtobufDeserializer.class.getName()),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-workflowengine-eventconsumer-" + instanceId),
                Map.entry(GROUP_ID_CONFIG, "dtrack-workflowengine"),
                Map.entry(ENABLE_AUTO_COMMIT_CONFIG, "false"),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest")));
        eventKafkaProducer = new KafkaProducer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-workflowengine-eventproducer-" + instanceId),
                Map.entry(KEY_SERIALIZER_CLASS_CONFIG, UUIDSerializer.class.getName()),
                Map.entry(VALUE_SERIALIZER_CLASS_CONFIG, WorkflowEventKafkaProtobufSerializer.class.getName()),
                Map.entry(COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name),
                Map.entry(LINGER_MS_CONFIG, "100"),
                Map.entry(ENABLE_IDEMPOTENCE_CONFIG, "true"),
                Map.entry(ACKS_CONFIG, "all")));
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            eventKafkaConsumerMetrics = new KafkaClientMetrics(eventKafkaConsumer);
            eventKafkaConsumerMetrics.bindTo(Metrics.getRegistry());
            eventKafkaProducerMetrics = new KafkaClientMetrics(eventKafkaProducer);
            eventKafkaProducerMetrics.bindTo(Metrics.getRegistry());
        }

        // TODO: Use uncaught exception handlers to signal back to the engine when
        //  threads die, so the engine can error out and shutdown, too.

        eventConsumer = new WorkflowEventConsumer(
                this,
                eventKafkaConsumer,
                /* batchLingerDuration */ Duration.ofSeconds(1),
                /* batchSize */ 500);
        eventKafkaConsumer.subscribe(List.of("dtrack.event.workflow"), eventConsumer);
        eventConsumerThread = new Thread(eventConsumer, "WorkflowEngine-EventConsumer");
        eventConsumerThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        eventConsumerThread.start();

        activityResultCompleter = new WorkflowActivityResultCompleter();
        activityResultCompleterThread = new Thread(activityResultCompleter, "WorkflowEngine-FutureResolver");
        activityResultCompleterThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        activityResultCompleterThread.start();

        scheduler = new WorkflowScheduler(this);
        schedulerExecutor = Executors.newSingleThreadScheduledExecutor(
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-Scheduler")
                        .build());
        schedulerExecutor.scheduleAtFixedRate(
                /* command */ scheduler,
                /* initialDelay */ 1,
                /* period */ 3,
                TimeUnit.SECONDS);

        setState(State.RUNNING);
    }

    public <T> CompletableFuture<WorkflowRun> startWorkflow(final StartWorkflowOptions<T> options) {
        state.assertRunning();

        final WorkflowRun workflowRun = inJdbiTransaction(handle -> {
            final WorkflowRunRow workflowRunRow = new WorkflowDao(handle).createRun(
                    new NewWorkflowRun(
                            UUID.randomUUID(),
                            options.name(),
                            options.version(),
                            options.priority(),
                            Instant.now()
                    ));

            return new WorkflowRun(workflowRunRow);
        });

        final WorkflowRunRequested.Builder runRequestedBuilder =
                WorkflowRunRequested.newBuilder()
                        .setName(workflowRun.workflowName())
                        .setVersion(workflowRun.workflowVersion());
        if (options.priority() != null) {
            runRequestedBuilder.setPriority(options.priority());
        }
        if (options.arguments() != null) {
            runRequestedBuilder.setArguments(serializeJson(options.arguments()));
        }

        return dispatchEvent(
                WorkflowEvent.newBuilder()
                        .setId(UUID.randomUUID().toString())
                        .setWorkflowRunId(workflowRun.id().toString())
                        .setTimestamp(Timestamps.now())
                        .setRunRequested(runRequestedBuilder.build())
                        .build())
                .thenApply(ignored -> workflowRun);
    }

    public <A, R> void registerWorkflowRunner(
            final String workflowName,
            final int concurrency,
            final WorkflowRunner<A, R> runner) {
        state.assertRunning();

        final String queue = "workflow-" + workflowName;
        if (taskExecutorByQueue.containsKey(queue)) {
            throw new IllegalStateException("A runner for workflow %s is already registered".formatted(workflowName));
        }

        // TODO: (Optionally) use virtual threads with semaphore?
        final ExecutorService executorService = Executors.newFixedThreadPool(concurrency,
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-WorkflowRunner-" + workflowName + "-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-WorkflowRunner-" + workflowName, null)
                    .bindTo(Metrics.getRegistry());
        }
        taskExecutorByQueue.put(queue, executorService);

        final WorkflowTaskContext.Factory<A, WorkflowRunContext<A>> contextFactory =
                polledTask -> new WorkflowRunContext<>(
                        runner.getClass(),
                        /* workflowEngine */ this,
                        polledTask.id(),
                        polledTask.queue(),
                        polledTask.priority(),
                        polledTask.workflowRunId(),
                        deserializeJson(polledTask.arguments(), new TypeReference<>() {
                        }));

        for (int i = 0; i < concurrency; i++) {
            executorService.execute(new WorkflowTaskCoordinator<>(this, runner, contextFactory, queue));
        }
    }

    public <A, R> void registerActivityRunner(
            final String activityName,
            final int concurrency,
            final WorkflowActivityRunner<A, R> runner) {
        state.assertRunning();

        final String queue = "activity-" + activityName;
        if (taskExecutorByQueue.containsKey(queue)) {
            throw new IllegalStateException(
                    "A runner for workflow activity %s is already registered".formatted(activityName));
        }

        // TODO: (Optionally) use virtual threads with semaphore?
        final ExecutorService executorService = Executors.newFixedThreadPool(concurrency,
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-ActivityRunner-" + activityName + "-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, "WorkflowEngine-ActivityRunner-" + activityName, null)
                    .bindTo(Metrics.getRegistry());
        }
        taskExecutorByQueue.put(queue, executorService);

        final WorkflowTaskContext.Factory<A, WorkflowActivityContext<A>> contextFactory =
                polledTask -> new WorkflowActivityContext<>(
                        polledTask.id(),
                        polledTask.queue(),
                        polledTask.priority(),
                        polledTask.workflowRunId(),
                        polledTask.activityName(),
                        polledTask.activityInvocationId(),
                        deserializeJson(polledTask.arguments(), new TypeReference<>() {
                        }));


        for (int i = 0; i < concurrency; i++) {
            executorService.execute(new WorkflowTaskCoordinator<>(this, runner, contextFactory, queue));
        }
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

        LOGGER.info("Waiting for executors to stop");
        for (final Map.Entry<String, ExecutorService> entry : taskExecutorByQueue.entrySet()) {
            final String queue = entry.getKey();
            final ExecutorService executorService = entry.getValue();

            executorService.shutdown();
            try {
                final boolean terminated = executorService.awaitTermination(30, TimeUnit.SECONDS);
                if (!terminated) {
                    LOGGER.warn("Executor for queue %s did not stop in time".formatted(queue));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        }
        taskExecutorByQueue.clear();

        LOGGER.info("Waiting for workflow event consumer to stop");
        eventConsumer.shutdown();
        try {
            final boolean terminated = eventConsumerThread.join(Duration.ofSeconds(30));
            if (!terminated) {
                LOGGER.warn("Workflow event consumer did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
        eventKafkaConsumer.close(Duration.ofSeconds(30));
        if (eventKafkaConsumerMetrics != null) {
            eventKafkaConsumerMetrics.close();
        }

        LOGGER.info("Waiting for event producer to stop");
        eventKafkaProducer.close(Duration.ofSeconds(30));
        if (eventKafkaProducerMetrics != null) {
            eventKafkaProducerMetrics.close();
        }

        LOGGER.info("Waiting for future resolver to stop");
        activityResultCompleter.shutdown();
        activityResultCompleterThread.interrupt();
        try {
            final boolean terminated = activityResultCompleterThread.join(Duration.ofSeconds(30));
            if (!terminated) {
                LOGGER.warn("Future resolver did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        LOGGER.info("Waiting for scheduler to stop");
        scheduler.shutdown();
        schedulerExecutor.shutdown();
        try {
            final boolean terminated = schedulerExecutor.awaitTermination(30, TimeUnit.SECONDS);
            if (!terminated) {
                LOGGER.warn("Scheduler did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
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

    JsonMapper jsonMapper() {
        return jsonMapper;
    }

    public WorkflowRun getWorkflowRun(final UUID workflowRunId) {
        final List<WorkflowRunRow> runRows = withJdbiHandle(
                handle -> new WorkflowDao(handle).getWorkflowRunsById(List.of(workflowRunId)));
        if (!runRows.isEmpty()) {
            return new WorkflowRun(runRows.getFirst());
        }

        return null;
    }

    public List<WorkflowRunLogEntryRow> getWorkflowRunLog(final UUID workflowRunId) {
        return withJdbiHandle(handle -> new WorkflowDao(handle).getWorkflowRunLog(workflowRunId));
    }

    String callActivity(
            final UUID invokingTaskId,
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final String arguments,
            final Duration timeout) {
        state.assertRunning();

        final var activityRunId = UUID.randomUUID();
        final var subjectBuilder = WorkflowActivityRunRequested.newBuilder()
                .setRunId(activityRunId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setInvokingTaskId(invokingTaskId.toString());
        if (arguments != null) {
            subjectBuilder.setArguments(arguments);
        }

        final var eventId = UUID.randomUUID();

        dispatchEvent(
                WorkflowEvent.newBuilder()
                        .setId(eventId.toString())
                        .setTimestamp(Timestamps.now())
                        .setWorkflowRunId(workflowRunId.toString())
                        .setActivityRunRequested(subjectBuilder.build())
                        .build())
                .join();

        final ActivityResultWatch resultWatch =
                activityResultCompleter.watchActivityResult(workflowRunId, activityName, invocationId);
        try {
            return resultWatch.result().get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            LOGGER.warn("Timed out while waiting for activity result; Suspending workflow run");
            resultWatch.cancel();
            throw new WorkflowRunSuspendedException(e,
                    WorkflowActivityCompletedResumeCondition.newBuilder()
                            .setRunId(activityRunId.toString())
                            .build());
        } catch (ExecutionException e) {
            throw new WorkflowActivityFailedException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WorkflowActivityFailedException(e);
        }
    }

    <A, R> R callLocalActivity(
            final UUID invokingTaskId,
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final A arguments,
            final Function<A, R> activityFunction) {
        state.assertRunning();

        final var eventsToDispatch = new ArrayList<WorkflowEvent>(2);

        final var activityRunId = UUID.randomUUID();
        final var executionStartedBuilder = WorkflowActivityRunStarted.newBuilder()
                .setRunId(activityRunId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setIsLocal(true)
                .setInvokingTaskId(invokingTaskId.toString());
        if (arguments != null) {
            executionStartedBuilder.setArguments(serializeJson(arguments));
        }
        eventsToDispatch.add(WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setWorkflowRunId(workflowRunId.toString())
                .setTimestamp(Timestamps.now())
                .setActivityRunStarted(executionStartedBuilder.build())
                .build());

        try {
            final R result = activityFunction.apply(arguments);

            final var executionCompletedBuilder = WorkflowActivityRunCompleted.newBuilder()
                    .setRunId(activityRunId.toString())
                    .setActivityName(activityName)
                    .setInvocationId(invocationId)
                    .setIsLocal(true)
                    .setInvokingTaskId(invokingTaskId.toString());
            if (result != null) {
                executionCompletedBuilder.setResult(serializeJson(result));
            }

            eventsToDispatch.add(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId.toString())
                    .setTimestamp(Timestamps.now())
                    .setActivityRunCompleted(executionCompletedBuilder.build())
                    .build());

            dispatchEvents(eventsToDispatch);
            return result;
        } catch (RuntimeException e) {
            eventsToDispatch.add(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId.toString())
                    .setTimestamp(Timestamps.now())
                    .setActivityRunFailed(WorkflowActivityRunFailed.newBuilder()
                            .setRunId(activityRunId.toString())
                            .setActivityName(activityName)
                            .setInvocationId(invocationId)
                            .setIsLocal(true)
                            .setFailureDetails(e.getMessage() != null
                                    ? e.getMessage()
                                    : e.getClass().getName())
                            .setInvokingTaskId(invokingTaskId.toString())
                            .build())
                    .build());

            // NB: Dispatch can also fail, but since the activityFunction execution
            // already failed there's no need to obstruct the original failure.
            dispatchEvents(eventsToDispatch).join();

            throw new WorkflowActivityFailedException(e);
        }
    }

    <T> T deserializeJson(final String json, final Class<T> clazz) {
        if (json == null || clazz == null) {
            return null;
        }

        try {
            return jsonMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    <T> T deserializeJson(final String json, final TypeReference<T> typeReference) {
        if (json == null || typeReference == null) {
            return null;
        }

        try {
            return jsonMapper.readValue(json, typeReference);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    <T> String serializeJson(final T object) {
        if (object == null) {
            return null;
        }

        try {
            return jsonMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    CompletableFuture<?> dispatchEvents(final List<WorkflowEvent> events) {
        final List<CompletableFuture<?>> futures = new ArrayList<>(events.size());

        for (final WorkflowEvent event : events) {
            final var future = new CompletableFuture<RecordMetadata>();
            futures.add(future);

            final var workflowRunId = UUID.fromString(event.getWorkflowRunId());
            final var producerRecord = new ProducerRecord<>("dtrack.event.workflow", workflowRunId, event);
            eventKafkaProducer.send(producerRecord, (metadata, exception) -> {
                if (exception != null) {
                    future.completeExceptionally(exception);
                } else {
                    future.complete(metadata);
                }
            });
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture<?>[0]));
    }

    CompletableFuture<?> dispatchEvent(final WorkflowEvent event) {
        return dispatchEvents(List.of(event));
    }

    @SuppressWarnings("UnusedReturnValue")
    CompletableFuture<?> dispatchTaskStartedEvent(final PolledWorkflowTaskRow task) {
        final var eventBuilder = WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setWorkflowRunId(task.workflowRunId().toString())
                .setTimestamp(Timestamps.fromMillis(task.startedAt().toEpochMilli()));

        if (task.activityName() == null) {
            if (task.previousStatus() == WorkflowTaskStatus.PENDING
                || task.previousStatus() == WorkflowTaskStatus.PENDING_RETRY) {
                eventBuilder.setRunStarted(
                        WorkflowRunStarted.newBuilder()
                                .setTaskId(task.id().toString())
                                .setAttempt(task.attempt()));
            } else if (task.previousStatus() == WorkflowTaskStatus.PENDING_RESUME) {
                eventBuilder.setRunResumed(
                        WorkflowRunResumed.newBuilder()
                                .setTaskId(task.id().toString())
                                .setAttempt(task.attempt()));
            } else {
                throw new IllegalStateException();
            }
        } else {
            final var subjectBuilder = WorkflowActivityRunStarted.newBuilder()
                    .setRunId(task.activityRunId().toString())
                    .setTaskId(task.id().toString())
                    .setActivityName(task.activityName())
                    .setInvocationId(task.activityInvocationId())
                    .setAttempt(task.attempt())
                    .setInvokingTaskId(task.invokingTaskId().toString());
            if (task.arguments() != null) {
                subjectBuilder.setArguments(task.arguments());
            }
            eventBuilder.setActivityRunStarted(subjectBuilder.build());
        }

        return dispatchEvent(eventBuilder.build());
    }

    @SuppressWarnings("UnusedReturnValue")
    <R> CompletableFuture<?> dispatchTaskCompletedEvent(final PolledWorkflowTaskRow task, final R result) {
        final WorkflowEvent.Builder eventBuilder = newEventBuilder(task);

        // We only persist timestamps in millisecond resolution,
        // but we also use them to achieve idempotency in event consumers.
        //
        // When start and completion of a job happened in the same millisecond,
        // event consumers would be unable to tell what happened first.
        //
        // If this condition occurs, assume completion to have happened a millisecond later.
        // Note that this would only ever happen if jobs are no-op and return immediately.
        if (Instant.now().toEpochMilli() == task.startedAt().toEpochMilli()) {
            eventBuilder.setTimestamp(Timestamps.fromMillis(task.startedAt().toEpochMilli() + 1));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Corrected timestamp for completion event");
            }
        }

        if (task.activityName() == null) {
            final var subjectBuilder = WorkflowRunCompleted.newBuilder()
                    .setTaskId(task.id().toString())
                    .setAttempt(task.attempt());
            if (result != null) {
                subjectBuilder.setResult(serializeJson(result));
            }
            eventBuilder.setRunCompleted(subjectBuilder.build());
        } else {
            final var subjectBuilder = WorkflowActivityRunCompleted.newBuilder()
                    .setRunId(task.activityRunId().toString())
                    .setTaskId(task.id().toString())
                    .setActivityName(task.activityName())
                    .setInvocationId(task.activityInvocationId())
                    .setAttempt(task.attempt())
                    .setInvokingTaskId(task.invokingTaskId().toString());
            if (result != null) {
                subjectBuilder.setResult(serializeJson(result));
            }

            eventBuilder.setActivityRunCompleted(subjectBuilder.build());
        }

        return dispatchEvent(eventBuilder.build());
    }

    @SuppressWarnings("UnusedReturnValue")
    CompletableFuture<?> dispatchTaskFailedEvent(final PolledWorkflowTaskRow task, final Throwable exception) {
        final WorkflowEvent.Builder eventBuilder = newEventBuilder(task);

        // We only persist timestamps in millisecond resolution,
        // but we also use them to achieve idempotency in event consumers.
        //
        // When start and failure of a job happened in the same millisecond,
        // event consumers would be unable to tell what happened first.
        //
        // If this condition occurs, assume failure to have happened a millisecond later.
        // Note that this would only ever happen if jobs are no-op and return immediately.
        if (Instant.now().toEpochMilli() == task.startedAt().toEpochMilli()) {
            eventBuilder.setTimestamp(Timestamps.fromMillis(task.startedAt().toEpochMilli() + 1));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Corrected timestamp for failure event");
            }
        }

        final String failureDetails = Optional.ofNullable(exception.getMessage())
                .orElse(exception.getClass().getName());

        Timestamp nextAttempt = null;
        if (exception instanceof AssertionError && (task.attempt() + 1) <= 6) {
            final long retryDelay = taskRetryIntervalFunction.apply(task.attempt());
            final Instant nextAttemptInstant = Instant.now().plusMillis(retryDelay);
            nextAttempt = Timestamps.fromMillis(nextAttemptInstant.toEpochMilli());
        }

        if (task.activityName() == null) {
            final var subjectBuilder = WorkflowRunFailed.newBuilder()
                    .setTaskId(task.id().toString())
                    .setAttempt(task.attempt())
                    .setFailureDetails(failureDetails);
            if (nextAttempt != null) {
                subjectBuilder.setNextAttemptAt(nextAttempt);
            }
            eventBuilder.setRunFailed(subjectBuilder.build());
        } else {
            final var subjectBuilder = WorkflowActivityRunFailed.newBuilder()
                    .setRunId(task.activityRunId().toString())
                    .setTaskId(task.id().toString())
                    .setActivityName(task.activityName())
                    .setInvocationId(task.activityInvocationId())
                    .setAttempt(task.attempt())
                    .setFailureDetails(failureDetails)
                    .setInvokingTaskId(task.invokingTaskId().toString());
            if (nextAttempt != null) {
                subjectBuilder.setNextAttemptAt(nextAttempt);
            }
            eventBuilder.setActivityRunFailed(subjectBuilder.build());
        }

        return dispatchEvent(eventBuilder.build());
    }

    CompletableFuture<?> dispatchTaskSuspendedEvent(
            final PolledWorkflowTaskRow task,
            final WorkflowActivityCompletedResumeCondition resumeCondition) {
        if (task.activityName() != null) {
            throw new IllegalStateException("");
        }

        return dispatchEvent(newEventBuilder(task)
                .setRunSuspended(WorkflowRunSuspended.newBuilder()
                        .setTaskId(task.id().toString())
                        .setAttempt(task.attempt())
                        .setActivityCompletedResumeCondition(resumeCondition)
                        .build())
                .build());
    }

    private static WorkflowEvent.Builder newEventBuilder(final PolledWorkflowTaskRow task) {
        return WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setTimestamp(Timestamps.now())
                .setWorkflowRunId(task.workflowRunId().toString());
    }

}
