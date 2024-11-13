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
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.serialization.UUIDDeserializer;
import org.apache.kafka.common.serialization.UUIDSerializer;
import org.dependencytrack.proto.workflow.v1alpha1.ExternalEventReceived;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowActivityRunStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunRequested;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunResumed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunStarted;
import org.dependencytrack.workflow.annotation.Workflow;
import org.dependencytrack.workflow.annotation.WorkflowActivity;
import org.dependencytrack.workflow.model.ScheduleWorkflowOptions;
import org.dependencytrack.workflow.model.StartWorkflowOptions;
import org.dependencytrack.workflow.model.WorkflowRun;
import org.dependencytrack.workflow.model.WorkflowTaskStatus;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.persistence.NewWorkflowRunRow;
import org.dependencytrack.workflow.persistence.NewWorkflowScheduleRow;
import org.dependencytrack.workflow.persistence.PolledWorkflowTaskRow;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.dependencytrack.workflow.persistence.WorkflowRunRow;
import org.dependencytrack.workflow.persistence.WorkflowScheduleRow;
import org.dependencytrack.workflow.serialization.WorkflowEventKafkaProtobufDeserializer;
import org.dependencytrack.workflow.serialization.WorkflowEventKafkaProtobufSerializer;
import org.jdbi.v3.core.statement.UnableToExecuteStatementException;

import java.io.Closeable;
import java.io.IOException;
import java.sql.BatchUpdateException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
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
import static org.dependencytrack.util.PersistenceUtil.getViolatedConstraint;

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

        boolean isStoppingOrStopped() {
            return equals(STOPPING) || equals(STOPPED);
        }

        boolean isNotStoppingOrStopped() {
            return !isStoppingOrStopped();
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

    static final int DEFAULT_TASK_RETRY_MAX_ATTEMPTS = 6;
    static final IntervalFunction DEFAULT_TASK_RETRY_INTERVAL_FUNCTION =
            IntervalFunction.ofExponentialRandomBackoff(
                    TimeUnit.SECONDS.toMillis(1), 1.5, 0.3, TimeUnit.SECONDS.toMillis(30));

    private final UUID instanceId = UUID.randomUUID();
    private volatile State state = State.CREATED;
    private final ReentrantLock stateLock = new ReentrantLock();
    private WorkflowEventConsumer eventConsumer;
    private Thread eventConsumerThread;
    private KafkaConsumer<UUID, WorkflowEvent> eventKafkaConsumer;
    private KafkaProducer<UUID, WorkflowEvent> eventKafkaProducer;
    private KafkaClientMetrics eventKafkaConsumerMetrics;
    private KafkaClientMetrics eventKafkaProducerMetrics;
    private ExecutorService taskDispatcherExecutor;
    private ScheduledExecutorService schedulerExecutor;
    private final Map<String, ExecutorService> taskExecutorByQueue = new HashMap<>();

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
                Map.entry(LINGER_MS_CONFIG, "5"),
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

        taskDispatcherExecutor = Executors.newThreadPerTaskExecutor(
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-TaskDispatcher-%d")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(taskDispatcherExecutor, "WorkflowEngine-TaskDispatcher", null)
                    .bindTo(Metrics.getRegistry());
        }

        final var scheduler = new WorkflowScheduler(this);
        schedulerExecutor = Executors.newSingleThreadScheduledExecutor(
                new BasicThreadFactory.Builder()
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .namingPattern("WorkflowEngine-Scheduler")
                        .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(schedulerExecutor, "WorkflowEngine-Scheduler", null)
                    .bindTo(Metrics.getRegistry());
        }
        schedulerExecutor.scheduleAtFixedRate(
                /* command */ scheduler,
                /* initialDelay */ 1,
                /* period */ 3,
                TimeUnit.SECONDS);

        setState(State.RUNNING);
    }

    public CompletableFuture<WorkflowRun> startWorkflow(final StartWorkflowOptions options) {
        state.assertRunning();

        final WorkflowRun workflowRun;
        try {
            workflowRun = inJdbiTransaction(handle -> {
                final WorkflowRunRow workflowRunRow =
                        new WorkflowDao(handle).createRun(
                                new NewWorkflowRunRow(
                                        UUID.randomUUID(),
                                        options.name(),
                                        options.version(),
                                        options.priority(),
                                        options.uniqueKey(),
                                        Instant.now()));

                return new WorkflowRun(workflowRunRow);
            });
        } catch (UnableToExecuteStatementException e) {
            if (e.getCause() instanceof final BatchUpdateException be
                && "WORKFLOW_RUN_UNIQUE_KEY_IDX".equals(
                    getViolatedConstraint(be.getNextException()))) {
                throw new IllegalStateException(
                        "Another workflow with unique key %s is already running".formatted(options.uniqueKey()));
            }

            throw e;
        }

        final WorkflowRunRequested.Builder runRequestedBuilder =
                WorkflowRunRequested.newBuilder()
                        .setName(workflowRun.workflowName())
                        .setVersion(workflowRun.workflowVersion());
        if (options.priority() != null) {
            runRequestedBuilder.setPriority(options.priority());
        }
        if (options.argument() != null) {
            runRequestedBuilder.setArgument(options.argument());
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Starting workflow run %s".formatted(workflowRun.id()));
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

    public void scheduleWorkflow(final ScheduleWorkflowOptions options) {
        state.assertRunning();
        requireNonNull(options, "options must not be null");
        requireNonNull(options.name(), "name must not be null");
        requireNonNull(options.cron(), "cron must not be null");
        requireNonNull(options.workflowName(), "workflowName must not be null");

        final Instant nextTrigger;
        try {
            final Schedule cronSchedule = Schedule.create(options.cron());
            nextTrigger = cronSchedule.next(new Date()).toInstant();
        } catch (InvalidExpressionException e) {
            throw new IllegalArgumentException(e);
        }

        try {
            final WorkflowScheduleRow ignoredForNow = inJdbiTransaction(
                    handle -> new WorkflowDao(handle).createSchedule(
                            new NewWorkflowScheduleRow(
                                    options.name(),
                                    options.cron(),
                                    options.workflowName(),
                                    options.workflowVersion(),
                                    options.priority(),
                                    options.uniqueKey(),
                                    options.argument(),
                                    nextTrigger)));
        } catch (UnableToExecuteStatementException e) {
            if (e.getCause() instanceof final BatchUpdateException be
                && "WORKFLOW_SCHEDULE_NAME_IDX".equals(
                    getViolatedConstraint(be.getNextException()))) {
                throw new IllegalStateException(
                        "Another schedule with name %s already exists".formatted(options.name()));
            }

            throw e;
        }
    }

    public <A, R> void registerWorkflowRunner(
            final WorkflowRunner<A, R> runner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(runner, "runner must not be null");

        final var workflowAnnotation = runner.getClass().getAnnotation(Workflow.class);
        if (workflowAnnotation == null) {
            throw new IllegalArgumentException();
        }

        registerWorkflowRunner(workflowAnnotation.name(), maxConcurrency, argumentConverter, resultConverter, runner);
    }

    <A, R> void registerWorkflowRunner(
            final String workflowName,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final WorkflowRunner<A, R> runner) {
        state.assertRunning();
        requireNonNull(workflowName, "workflowName must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(runner, "runner must not be null");

        final String queue = "workflow-" + workflowName;
        if (taskExecutorByQueue.containsKey(queue)) {
            throw new IllegalStateException("A runner for workflow %s is already registered".formatted(workflowName));
        }

        // TODO: (Optionally) use virtual threads with semaphore?
        final ExecutorService executorService = Executors.newFixedThreadPool(maxConcurrency,
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
                        polledTask.workflowName(),
                        polledTask.workflowVersion(),
                        polledTask.workflowRunId(),
                        argumentConverter.convertFromPayload(
                                polledTask.argument()).orElse(null));

        taskDispatcherExecutor.execute(new WorkflowTaskDispatcher<>(
                /* engine */ this,
                executorService,
                runner,
                contextFactory,
                resultConverter,
                queue,
                maxConcurrency));
    }

    public <A, R> void registerActivityRunner(
            final WorkflowActivityRunner<A, R> runner,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        requireNonNull(runner, "runner must not be null");

        final var activityAnnotation = runner.getClass().getAnnotation(WorkflowActivity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException();
        }

        registerActivityRunner(activityAnnotation.name(), maxConcurrency, argumentConverter, resultConverter, runner);
    }

    <A, R> void registerActivityRunner(
            final String activityName,
            final int maxConcurrency,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final WorkflowActivityRunner<A, R> runner) {
        state.assertRunning();
        requireNonNull(activityName, "activityName must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(runner, "runner must not be null");

        final String queue = "activity-" + activityName;
        if (taskExecutorByQueue.containsKey(queue)) {
            throw new IllegalStateException(
                    "A runner for workflow activity %s is already registered".formatted(activityName));
        }

        // TODO: (Optionally) use virtual threads with semaphore?
        final ExecutorService executorService = Executors.newFixedThreadPool(maxConcurrency,
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
                        polledTask.workflowName(),
                        polledTask.workflowVersion(),
                        polledTask.workflowRunId(),
                        polledTask.activityName(),
                        polledTask.activityInvocationId(),
                        argumentConverter.convertFromPayload(
                                polledTask.argument()).orElse(null));


        taskDispatcherExecutor.execute(new WorkflowTaskDispatcher<>(
                /* engine */ this,
                executorService,
                runner,
                contextFactory,
                resultConverter,
                queue,
                maxConcurrency));
    }

    public <T> CompletableFuture<?> sendExternalEvent(
            final UUID workflowRunId,
            final UUID externalEventId,
            final T content,
            final PayloadConverter<T> contentConverter) {
        requireNonNull(workflowRunId, "workflowRunId must not be null");
        requireNonNull(externalEventId, "externalEventId must not be null");

        if (!withJdbiHandle(handle -> new WorkflowDao(handle).doesRunExist(workflowRunId))) {
            throw new IllegalStateException(
                    "A workflow run with ID %s does not exist".formatted(workflowRunId));
        }

        final var subjectBuilder = ExternalEventReceived.newBuilder()
                .setId(externalEventId.toString());
        if (content != null) {
            contentConverter.convertToPayload(content)
                    .ifPresent(subjectBuilder::setPayload);
        }

        return dispatchEvent(WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setWorkflowRunId(workflowRunId.toString())
                .setTimestamp(Timestamps.now())
                .setExternalEventReceived(subjectBuilder.build())
                .build());
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

        LOGGER.info("Waiting for task dispatchers to stop");
        taskDispatcherExecutor.shutdown();
        try {
            final boolean terminated = taskDispatcherExecutor.awaitTermination(30, TimeUnit.SECONDS);
            if (!terminated) {
                LOGGER.warn("Task dispatchers did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for task dispatchers to stop", e);
        }

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

        LOGGER.info("Waiting for scheduler to stop");
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

    public WorkflowRun getWorkflowRun(final UUID workflowRunId) {
        final List<WorkflowRunRow> runRows = withJdbiHandle(
                handle -> new WorkflowDao(handle).getWorkflowRunsById(List.of(workflowRunId)));
        if (!runRows.isEmpty()) {
            return new WorkflowRun(runRows.getFirst());
        }

        return null;
    }

    public List<WorkflowEvent> getWorkflowRunEventLog(final UUID workflowRunId) {
        return withJdbiHandle(handle -> new WorkflowDao(handle).getWorkflowRunEventLog(workflowRunId));
    }

    <R> Optional<R> callActivity(
            final UUID invokingTaskId,
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final WorkflowPayload argumentPayload,
            final Consumer<WorkflowEvent> eventConsumer) {
        state.assertRunning();

        final var completionId = UUID.randomUUID();
        final var subjectBuilder = WorkflowActivityRunRequested.newBuilder()
                .setCompletionId(completionId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setInvokingTaskId(invokingTaskId.toString());
        if (argumentPayload != null) {
            subjectBuilder.setArgument(argumentPayload);
        }

        eventConsumer.accept(
                WorkflowEvent.newBuilder()
                        .setId(UUID.randomUUID().toString())
                        .setTimestamp(Timestamps.now())
                        .setWorkflowRunId(workflowRunId.toString())
                        .setActivityRunRequested(subjectBuilder.build())
                        .build());

        // TODO: Return an awaitable instead.
        throw new WorkflowRunSuspendedException(completionId);
    }

    <A, R> Optional<R> callLocalActivity(
            final UUID invokingTaskId,
            final UUID workflowRunId,
            final String activityName,
            final String invocationId,
            final A argument,
            final WorkflowPayload argumentPayload,
            final PayloadConverter<R> resultConverter,
            final Function<A, Optional<R>> activityFunction,
            final Consumer<WorkflowEvent> eventConsumer) {
        state.assertRunning();

        final var completionId = UUID.randomUUID();
        final var executionStartedBuilder = WorkflowActivityRunStarted.newBuilder()
                .setCompletionId(completionId.toString())
                .setActivityName(activityName)
                .setInvocationId(invocationId)
                .setIsLocal(true)
                .setInvokingTaskId(invokingTaskId.toString());
        if (argumentPayload != null) {
            executionStartedBuilder.setArgument(argumentPayload);
        }
        eventConsumer.accept(WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setWorkflowRunId(workflowRunId.toString())
                .setTimestamp(Timestamps.now())
                .setActivityRunStarted(executionStartedBuilder.build())
                .build());

        try {
            final Optional<R> optionalResult = activityFunction.apply(argument);

            final var executionCompletedBuilder = WorkflowActivityRunCompleted.newBuilder()
                    .setCompletionId(completionId.toString())
                    .setActivityName(activityName)
                    .setInvocationId(invocationId)
                    .setIsLocal(true)
                    .setInvokingTaskId(invokingTaskId.toString());
            optionalResult
                    .flatMap(resultConverter::convertToPayload)
                    .ifPresent(executionCompletedBuilder::setResult);

            eventConsumer.accept(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId.toString())
                    .setTimestamp(Timestamps.now())
                    .setActivityRunCompleted(executionCompletedBuilder.build())
                    .build());

            return optionalResult;
        } catch (RuntimeException e) {
            eventConsumer.accept(WorkflowEvent.newBuilder()
                    .setId(UUID.randomUUID().toString())
                    .setWorkflowRunId(workflowRunId.toString())
                    .setTimestamp(Timestamps.now())
                    .setActivityRunFailed(WorkflowActivityRunFailed.newBuilder()
                            .setCompletionId(completionId.toString())
                            .setActivityName(activityName)
                            .setInvocationId(invocationId)
                            .setIsLocal(true)
                            .setFailureDetails(e.getMessage() != null
                                    ? e.getMessage()
                                    : e.getClass().getName())
                            .setInvokingTaskId(invokingTaskId.toString())
                            .build())
                    .build());

            throw new WorkflowActivityFailedException(e);
        }
    }

    CompletableFuture<?> dispatchEvents(final List<WorkflowEvent> events) {
        if (events.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }

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

    WorkflowEvent createTaskStartedEvent(final PolledWorkflowTaskRow task) {
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
                    .setCompletionId(task.completionId().toString())
                    .setTaskId(task.id().toString())
                    .setActivityName(task.activityName())
                    .setInvocationId(task.activityInvocationId())
                    .setAttempt(task.attempt())
                    .setInvokingTaskId(task.invokingTaskId().toString());
            if (task.argument() != null) {
                subjectBuilder.setArgument(task.argument());
            }
            eventBuilder.setActivityRunStarted(subjectBuilder.build());
        }

        return eventBuilder.build();
    }

    WorkflowEvent createTaskCompletedEvent(
            final PolledWorkflowTaskRow task,
            final WorkflowPayload result) {
        final WorkflowEvent.Builder eventBuilder = newEventBuilder(task);

        if (task.activityName() == null) {
            final var subjectBuilder = WorkflowRunCompleted.newBuilder()
                    .setTaskId(task.id().toString())
                    .setAttempt(task.attempt());
            if (result != null) {
                subjectBuilder.setResult(result);
            }
            eventBuilder.setRunCompleted(subjectBuilder.build());
        } else {
            final var subjectBuilder = WorkflowActivityRunCompleted.newBuilder()
                    .setCompletionId(task.completionId().toString())
                    .setTaskId(task.id().toString())
                    .setActivityName(task.activityName())
                    .setInvocationId(task.activityInvocationId())
                    .setAttempt(task.attempt())
                    .setInvokingTaskId(task.invokingTaskId().toString());
            if (result != null) {
                subjectBuilder.setResult(result);
            }

            eventBuilder.setActivityRunCompleted(subjectBuilder.build());
        }

        return eventBuilder.build();
    }

    WorkflowEvent createTaskFailedEvent(final PolledWorkflowTaskRow task, final Throwable exception) {
        final WorkflowEvent.Builder eventBuilder = newEventBuilder(task);

        final boolean isTerminal = exception instanceof TerminalWorkflowException;
        final String failureDetails = ExceptionUtils.getStackTrace(exception);

        if (task.activityName() == null) {
            eventBuilder.setRunFailed(WorkflowRunFailed.newBuilder()
                    .setTaskId(task.id().toString())
                    .setAttempt(task.attempt())
                    .setIsTerminalFailure(isTerminal)
                    .setFailureDetails(failureDetails)
                    .build());
        } else {
            eventBuilder.setActivityRunFailed(WorkflowActivityRunFailed.newBuilder()
                    .setCompletionId(task.completionId().toString())
                    .setTaskId(task.id().toString())
                    .setActivityName(task.activityName())
                    .setInvocationId(task.activityInvocationId())
                    .setAttempt(task.attempt())
                    .setIsTerminalFailure(isTerminal)
                    .setFailureDetails(failureDetails)
                    .setInvokingTaskId(task.invokingTaskId().toString())
                    .build());
        }

        return eventBuilder.build();
    }

    private static WorkflowEvent.Builder newEventBuilder(final PolledWorkflowTaskRow task) {
        return WorkflowEvent.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setTimestamp(Timestamps.now())
                .setWorkflowRunId(task.workflowRunId().toString());
    }

    static Optional<UUID> extractCompletionId(final WorkflowEvent event) {
        final String completionId = switch (event.getSubjectCase()) {
            case ACTIVITY_RUN_REQUESTED -> event.getActivityRunRequested().getCompletionId();
            case ACTIVITY_RUN_QUEUED -> event.getActivityRunQueued().getCompletionId();
            case ACTIVITY_RUN_STARTED -> event.getActivityRunStarted().getCompletionId();
            case ACTIVITY_RUN_COMPLETED -> event.getActivityRunCompleted().getCompletionId();
            case ACTIVITY_RUN_FAILED -> event.getActivityRunFailed().getCompletionId();
            case EXTERNAL_EVENT_AWAITED -> event.getExternalEventAwaited().getCompletionId();
            default -> null;
        };

        return Optional.ofNullable(completionId).map(UUID::fromString);
    }

}
