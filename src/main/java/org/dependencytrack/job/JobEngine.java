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

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import io.micrometer.core.instrument.binder.kafka.KafkaClientMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.serialization.LongDeserializer;
import org.apache.kafka.common.serialization.LongSerializer;
import org.dependencytrack.job.event.JobEventConsumer;
import org.dependencytrack.job.event.JobEventKafkaProtobufDeserializer;
import org.dependencytrack.job.event.JobEventKafkaProtobufSerializer;
import org.dependencytrack.job.persistence.JobDao;
import org.dependencytrack.job.persistence.JobScheduleDao;
import org.dependencytrack.job.persistence.JobScheduleTriggerUpdate;
import org.dependencytrack.job.persistence.PolledJob;
import org.dependencytrack.proto.job.v1alpha1.JobEvent;
import org.dependencytrack.proto.job.v1alpha1.JobEvent.JobCompletedSubject;
import org.dependencytrack.proto.job.v1alpha1.JobEvent.JobFailedSubject;
import org.dependencytrack.proto.job.v1alpha1.JobEvent.JobQueuedSubject;
import org.dependencytrack.proto.job.v1alpha1.JobEvent.JobStartedSubject;
import org.slf4j.MDC;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

// TODO: Metrics instrumentation
public class JobEngine implements Closeable {

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

        private boolean isNotStoppingOrStopped() {
            return !equals(STOPPING) && !equals(STOPPED);
        }

        private void assertRunning() {
            if (!equals(RUNNING)) {
                throw new IllegalStateException(
                        "Engine must be in state %s, but is %s".formatted(RUNNING, this));
            }
        }

    }

    private static final Logger LOGGER = Logger.getLogger(JobEngine.class);
    private static final JobEngine INSTANCE = new JobEngine();

    private final UUID instanceId = UUID.randomUUID();
    private volatile State state = State.CREATED;
    private final ReentrantLock stateLock = new ReentrantLock();
    private JobEventConsumer eventConsumer;
    private Thread eventConsumerThread;
    private KafkaConsumer<Long, JobEvent> kafkaEventConsumer;
    private KafkaProducer<Long, JobEvent> kafkaEventProducer;
    private KafkaClientMetrics kafkaEventConsumerMetrics;
    private KafkaClientMetrics kafkaEventProducerMetrics;
    private ScheduledExecutorService schedulerExecutor;
    private final Map<String, ExecutorService> executorByKind = new ConcurrentHashMap<>();
    private final IntervalFunction retryIntervalFunction =
            IntervalFunction.ofExponentialRandomBackoff(250, 1.5, 0.3, 5000);

    public static JobEngine getInstance() {
        return INSTANCE;
    }

    public void start() {
        setState(State.STARTING);

        kafkaEventProducer = new KafkaProducer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-jobengine-jobeventproducer-" + instanceId),
                Map.entry(KEY_SERIALIZER_CLASS_CONFIG, LongSerializer.class.getName()),
                Map.entry(VALUE_SERIALIZER_CLASS_CONFIG, JobEventKafkaProtobufSerializer.class.getName()),
                Map.entry(COMPRESSION_TYPE_CONFIG, CompressionType.SNAPPY.name),
                Map.entry(LINGER_MS_CONFIG, "100"),
                Map.entry(ENABLE_IDEMPOTENCE_CONFIG, "true"),
                Map.entry(ACKS_CONFIG, "all")));
        kafkaEventConsumer = new KafkaConsumer<>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, Config.getInstance().getProperty(KAFKA_BOOTSTRAP_SERVERS)),
                Map.entry(CLIENT_ID_CONFIG, "dtrack-jobengine-jobeventconsumer-" + instanceId),
                Map.entry(GROUP_ID_CONFIG, "dtrack-jobengine"),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, LongDeserializer.class.getName()),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, JobEventKafkaProtobufDeserializer.class.getName()),
                Map.entry(ENABLE_AUTO_COMMIT_CONFIG, "false"),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest")));
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            kafkaEventConsumerMetrics = new KafkaClientMetrics(kafkaEventConsumer);
            kafkaEventConsumerMetrics.bindTo(Metrics.getRegistry());
            kafkaEventProducerMetrics = new KafkaClientMetrics(kafkaEventProducer);
            kafkaEventProducerMetrics.bindTo(Metrics.getRegistry());
        }

        eventConsumer = new JobEventConsumer(
                kafkaEventConsumer,
                /* batchLingerDuration */ Duration.ofMillis(500), // TODO: Read from config.
                /* batchSize */ 1000); // TODO: Read from config.
        kafkaEventConsumer.subscribe(List.of("dtrack.event.job"), eventConsumer);
        eventConsumerThread = new Thread(eventConsumer, "JobEngine-JobEventConsumer");
        eventConsumerThread.setUncaughtExceptionHandler(new LoggableUncaughtExceptionHandler());
        eventConsumerThread.start();

        schedulerExecutor = Executors.newSingleThreadScheduledExecutor(new BasicThreadFactory.Builder()
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .namingPattern("JobEngine-Scheduler-%d")
                .build());
        schedulerExecutor.scheduleAtFixedRate(
                this::scheduleDueJobs,
                /* initialDelay */ 1,
                /* period */ 5,
                TimeUnit.SECONDS);

        setState(State.RUNNING);
    }

    public void registerWorker(final String kind, final int concurrency, final JobWorker worker) {
        state.assertRunning();

        if (executorByKind.containsKey(kind)) {
            throw new IllegalStateException("A worker for job kind %s is already registered".formatted(kind));
        }

        // TODO: (Optionally) use virtual threads with semaphore?
        final ExecutorService es = Executors.newFixedThreadPool(concurrency, new BasicThreadFactory.Builder()
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .namingPattern("JobEngine-Worker-" + kind + "-%d")
                .build());
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(es, "JobEngine-Worker-" + kind, null)
                    .bindTo(Metrics.getRegistry());
        }
        executorByKind.put(kind, es);
        final var intervalFunction = IntervalFunction.ofExponentialRandomBackoff(
                /* initialIntervalMillis */ 250,
                /* multiplier */ 1.5,
                /* randomizationFactor */ 0.3,
                /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(5));

        for (int i = 0; i < concurrency; i++) {
            final var workerThreadId = UUID.randomUUID();
            es.execute(() -> {
                try (var ignoredMdcJobWorker = MDC.putCloseable("jobWorker", worker.getClass().getSimpleName());
                     var ignoredMdcJobWorkerThreadId = MDC.putCloseable("jobWorkerThread", workerThreadId.toString())) {
                    final var pollMisses = new AtomicInteger(0);
                    while (state.isNotStoppingOrStopped()) {
                        final PolledJob polledJob;
                        final Timer.Sample pollTimerSample = Timer.start();
                        try {
                            polledJob = inJdbiTransaction(handle -> new JobDao(handle).poll(kind)).orElse(null);
                        } finally {
                            pollTimerSample.stop(Timer
                                    .builder("job_engine_poll")
                                    .register(Metrics.getRegistry()));
                        }
                        if (polledJob == null) {
                            final long backoffMs = intervalFunction.apply(pollMisses.incrementAndGet());
                            LOGGER.debug("Backing off for %dms".formatted(backoffMs));
                            try {
                                Thread.sleep(backoffMs);
                                continue;
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new RuntimeException(e);
                            }
                        }

                        pollMisses.set(0);
                        dispatchJobStartedEvent(polledJob);

                        final Timer.Sample processingTimerSample = Timer.start();
                        try (var ignoredMdcJobId = MDC.putCloseable("jobId", String.valueOf(polledJob.id()));
                             var ignoredMdcJobKind = MDC.putCloseable("jobKind", polledJob.kind());
                             var ignoredMdcJobPriority = MDC.putCloseable("jobPriority", String.valueOf(polledJob.priority()));
                             var ignoredMdcJobAttempts = MDC.putCloseable("jobAttempt", String.valueOf(polledJob.attempt()))) {
                            LOGGER.debug("Processing");
                            worker.process(polledJob);
                            dispatchJobCompletedEvent(polledJob);
                            LOGGER.debug("Job completed successfully");
                        } catch (Exception e) {
                            final JobFailedSubject.Builder subjectBuilder = JobFailedSubject.newBuilder()
                                    .setAttempt(polledJob.attempt())
                                    .setFailureReason(e.getMessage());
                            if (e instanceof TransientJobException && (polledJob.attempt() + 1) <= 6) {
                                final long retryDelay = retryIntervalFunction.apply(polledJob.attempt());
                                final Instant nextAttempt = Instant.now().plusMillis(retryDelay);
                                subjectBuilder.setNextAttemptAt(Timestamps.fromMillis(nextAttempt.toEpochMilli()));
                            }

                            dispatchJobFailedEvent(polledJob, subjectBuilder.build());
                            LOGGER.debug("Job failed", e);
                        } finally {
                            processingTimerSample.stop(Timer
                                    .builder("job_worker_process")
                                    .register(Metrics.getRegistry()));
                        }
                    }
                }
            });
        }
    }

    public List<QueuedJob> enqueueAll(final Collection<NewJob> newJobs) {
        state.assertRunning();

        final List<QueuedJob> queuedJobs = inJdbiTransaction(
                handle -> new JobDao(handle).enqueueAll(newJobs));
        dispatchJobQueuedEvents(queuedJobs);

        return queuedJobs;
    }

    public QueuedJob enqueue(final NewJob newJob) {
        final List<QueuedJob> queuedJobs = enqueueAll(List.of(newJob));
        if (queuedJobs.size() != 1) {
            throw new IllegalStateException("Job was not queued");
        }

        return queuedJobs.getFirst();
    }

    public List<JobSchedule> scheduleAll(final Collection<NewJobSchedule> schedules) {
        return inJdbiTransaction(handle -> new JobScheduleDao(handle).createAll(schedules.stream()
                .map(schedule -> {
                    final Schedule cronSchedule;
                    try {
                        cronSchedule = Schedule.create(schedule.cron());
                    } catch (InvalidExpressionException e) {
                        throw new IllegalArgumentException(
                                "Failed to parse cron expression for %s".formatted(schedule), e);
                    }

                    if (schedule.nextTrigger() != null) {
                        return schedule;
                    }

                    return new NewJobSchedule(
                            schedule.name(),
                            schedule.cron(),
                            schedule.jobKind(),
                            schedule.jobPriority(),
                            cronSchedule.next().toInstant());
                })
                .toList()));
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

        LOGGER.info("Waiting for scheduler to stop");
        schedulerExecutor.shutdown();
        try {
            final boolean terminated = schedulerExecutor.awaitTermination(30, TimeUnit.SECONDS);
            if (!terminated) {
                LOGGER.warn("Scheduler did not terminate in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        LOGGER.info("Waiting for workers to stop");
        for (final Map.Entry<String, ExecutorService> entry : executorByKind.entrySet()) {
            final String kind = entry.getKey();
            final ExecutorService executorService = entry.getValue();

            executorService.shutdown();
            try {
                final boolean terminated = executorService.awaitTermination(30, TimeUnit.SECONDS);
                if (!terminated) {
                    LOGGER.warn("Executor for kind %s did not stop in time".formatted(kind));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        }
        executorByKind.clear();

        LOGGER.info("Waiting for event consumer to stop");
        eventConsumer.shutdown();
        try {
            final boolean terminated = eventConsumerThread.join(Duration.ofSeconds(30));
            if (!terminated) {
                LOGGER.warn("Event consumer did not stop in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        kafkaEventConsumer.close(Duration.ofSeconds(30));
        if (kafkaEventConsumerMetrics != null) {
            kafkaEventConsumerMetrics.close();
        }

        LOGGER.info("Waiting for event producer to stop");
        kafkaEventProducer.close(Duration.ofSeconds(30));
        if (kafkaEventProducerMetrics != null) {
            kafkaEventProducerMetrics.close();
        }

        setState(State.STOPPED);
    }

    private void scheduleDueJobs() {
        final var queuedJobs = new ArrayList<QueuedJob>();

        useJdbiTransaction(handle -> {
            final var jobDao = new JobDao(handle);
            final var jobScheduleDao = new JobScheduleDao(handle);

            final List<JobSchedule> dueSchedules = jobScheduleDao.getAllDue();
            if (dueSchedules.isEmpty()) {
                LOGGER.debug("No due schedules");
                return;
            }

            final var jobsToQueue = dueSchedules.stream()
                    .map(schedule -> new NewJob(schedule.jobKind())
                            .withPriority(schedule.jobPriority()))
                    .toList();

            queuedJobs.addAll(jobDao.enqueueAll(jobsToQueue));
            if (LOGGER.isDebugEnabled()) {
                for (final QueuedJob queuedJob : queuedJobs) {
                    LOGGER.debug("Queued %s".formatted(queuedJob));
                }
            }

            final List<JobScheduleTriggerUpdate> triggerUpdates = dueSchedules.stream()
                    .map(schedule -> {
                        final Schedule cronSchedule;
                        try {
                            cronSchedule = Schedule.create(schedule.cron());
                        } catch (InvalidExpressionException e) {
                            LOGGER.warn("Failed to parse cron expression for %s".formatted(schedule), e);
                            return null;
                        }
                        final Instant nextTrigger = cronSchedule.next().toInstant();
                        return new JobScheduleTriggerUpdate(schedule.id(), nextTrigger);
                    })
                    .filter(Objects::nonNull)
                    .toList();
            final List<JobSchedule> updatedSchedules = jobScheduleDao.updateAllTriggers(triggerUpdates);
            if (LOGGER.isDebugEnabled()) {
                for (final JobSchedule updatedSchedule : updatedSchedules) {
                    LOGGER.debug("Updated schedule: %s".formatted(updatedSchedule));
                }
            }
        });

        dispatchJobQueuedEvents(queuedJobs);
    }

    @SuppressWarnings("UnusedReturnValue")
    private CompletableFuture<?> dispatchJobCompletedEvent(final PolledJob job) {
        final JobEvent.Builder eventBuilder = newEventBuilder(job);

        // We only persist timestamps in millisecond resolution,
        // but we also use them to achieve idempotency in event consumers.
        //
        // When start and completion of a job happened in the same millisecond,
        // event consumers would be unable to tell what happened first.
        //
        // If this condition occurs, assume completion to have happened a millisecond later.
        // Note that this would only ever happen if jobs are no-op and return immediately.
        if (Instant.now().toEpochMilli() == job.startedAt().toEpochMilli()) {
            eventBuilder.setTimestamp(Timestamps.fromMillis(job.startedAt().toEpochMilli() + 1));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Corrected timestamp for completion event");
            }
        }

        return dispatchEvents(List.of(eventBuilder
                .setJobCompletedSubject(JobCompletedSubject.newBuilder()
                        .setAttempt(job.attempt())
                        .build())
                .build()));
    }

    @SuppressWarnings("UnusedReturnValue")
    private CompletableFuture<?> dispatchJobFailedEvent(final PolledJob job, JobFailedSubject subject) {
        final JobEvent.Builder eventBuilder = newEventBuilder(job);

        // We only persist timestamps in millisecond resolution,
        // but we also use them to achieve idempotency in event consumers.
        //
        // When start and failure of a job happened in the same millisecond,
        // event consumers would be unable to tell what happened first.
        //
        // If this condition occurs, assume failure to have happened a millisecond later.
        // Note that this would only ever happen if jobs are no-op and return immediately.
        if (Instant.now().toEpochMilli() == job.startedAt().toEpochMilli()) {
            eventBuilder.setTimestamp(Timestamps.fromMillis(job.startedAt().toEpochMilli() + 1));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Corrected timestamp for failure event");
            }
        }

        return dispatchEvents(List.of(eventBuilder
                .setJobFailedSubject(subject)
                .build()));
    }

    @SuppressWarnings("UnusedReturnValue")
    private CompletableFuture<?> dispatchJobQueuedEvents(final List<QueuedJob> jobs) {
        return dispatchEvents(jobs.stream()
                .map(job -> newEventBuilder(job)
                        .setTimestamp(Timestamps.fromMillis(job.createdAt().toEpochMilli()))
                        .setJobQueuedSubject(JobQueuedSubject.newBuilder())
                        .build())
                .toList());
    }

    @SuppressWarnings("UnusedReturnValue")
    private CompletableFuture<?> dispatchJobStartedEvent(final PolledJob job) {
        return dispatchEvents(List.of(newEventBuilder(job)
                .setTimestamp(Timestamps.fromMillis(job.startedAt().toEpochMilli()))
                .setJobStartedSubject(JobStartedSubject.newBuilder()
                        .setAttempt(job.attempt())
                        .build())
                .build()));
    }

    private CompletableFuture<?> dispatchEvents(final List<JobEvent> events) {
        if (events.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }

        final var sendFutures = new ArrayList<CompletableFuture<RecordMetadata>>(events.size());
        for (final JobEvent event : events) {
            final var sendFuture = new CompletableFuture<RecordMetadata>();
            sendFutures.add(sendFuture);

            final var producerRecord = new ProducerRecord<>("dtrack.event.job", event.getJobId(), event);
            kafkaEventProducer.send(producerRecord, (metadata, exception) -> {
                if (exception != null) {
                    try {
                        // JSON is easier to read in logs than the default text format.
                        final String eventJson = JsonFormat.printer().print(event);
                        LOGGER.error("Failed to produce %s".formatted(eventJson), exception);
                    } catch (InvalidProtocolBufferException e) {
                        LOGGER.warn("Failed to serialize event as JSON", e);
                        LOGGER.error("Failed to produce %s".formatted(event), exception);
                    }

                    sendFuture.completeExceptionally(exception);
                } else {
                    sendFuture.complete(metadata);
                }
            });
        }

        if (sendFutures.size() == 1) {
            return sendFutures.getFirst();
        }

        return CompletableFuture.allOf(sendFutures.toArray(new CompletableFuture[0]));
    }

    private static JobEvent.Builder newEventBuilder(final PolledJob job) {
        return JobEvent.newBuilder()
                .setJobId(job.id())
                .setJobKind(job.kind())
                .setTimestamp(Timestamps.now())
                .setWorkflowStepRunId(job.workflowStepRunId() != null
                        ? job.workflowStepRunId()
                        : 0);
    }

    private static JobEvent.Builder newEventBuilder(final QueuedJob job) {
        return JobEvent.newBuilder()
                .setJobId(job.id())
                .setJobKind(job.kind())
                .setTimestamp(Timestamps.now())
                .setWorkflowStepRunId(job.workflowStepRunId() != null
                        ? job.workflowStepRunId()
                        : 0);
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