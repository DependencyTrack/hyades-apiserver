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

import alpine.common.logging.Logger;
import alpine.common.metrics.Metrics;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowPayload;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowRunSuspended;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.persistence.PolledWorkflowTaskRow;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.slf4j.MDC;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_COMPLETION_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_RUN_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_ATTEMPT;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_PRIORITY;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_QUEUE;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_RUNNER;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

final class WorkflowTaskDispatcher<A, R, C extends WorkflowTaskContext<A>> implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowTaskDispatcher.class);
    private static final IntervalFunction POLL_BACKOFF_INTERVAL_FUNCTION =
            IntervalFunction.ofExponentialRandomBackoff(
                    /* initialIntervalMillis */ 500,
                    /* multiplier */ 1.5,
                    /* randomizationFactor */ 0.3,
                    /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(5));

    private final WorkflowEngine engine;
    private final ExecutorService taskExecutor;
    private final WorkflowTaskRunner<A, R, C> taskRunner;
    private final Logger taskRunnerLogger;
    private final WorkflowTaskContext.Factory<A, C> taskContextFactory;
    private final PayloadConverter<R> taskResultConverter;
    private final String taskQueueName;
    private final Semaphore taskSemaphore;

    WorkflowTaskDispatcher(
            final WorkflowEngine engine,
            final ExecutorService taskExecutor,
            final WorkflowTaskRunner<A, R, C> taskRunner,
            final WorkflowTaskContext.Factory<A, C> taskContextFactory,
            final PayloadConverter<R> taskResultConverter,
            final String taskQueueName,
            final int maxConcurrency) {
        this.engine = engine;
        this.taskExecutor = taskExecutor;
        this.taskRunner = taskRunner;
        this.taskRunnerLogger = Logger.getLogger(taskRunner.getClass());
        this.taskContextFactory = taskContextFactory;
        this.taskResultConverter = taskResultConverter;
        this.taskQueueName = taskQueueName;
        this.taskSemaphore = new Semaphore(maxConcurrency);
    }

    @Override
    public void run() {
        try (var ignoredMdcTaskQueue = MDC.putCloseable(MDC_WORKFLOW_TASK_QUEUE, taskQueueName);
             var ignoredMdcTaskRunner = MDC.putCloseable(MDC_WORKFLOW_TASK_RUNNER, taskRunner.getClass().getSimpleName())) {
            runInternal();
        }
    }

    private void runInternal() {
        int pollsWithoutResults = 0;

        while (engine.state().isNotStoppingOrStopped()) {
            // Attempt to acquire a permit from the semaphore, blocking for up to 5 seconds.
            // If acquisition was successful, immediately release the permit again.
            // This is a poor-man's alternative to busy-waiting on taskSemaphore.availablePermits() > 0.
            try {
                boolean acquired = taskSemaphore.tryAcquire(5, TimeUnit.SECONDS);
                if (!acquired) {
                    LOGGER.debug("All task executors busy, nothing to poll");
                    pollsWithoutResults = 0; // Already waited longer than the max poll backoff.
                    continue;
                }

                taskSemaphore.release();
            } catch (InterruptedException e) {
                LOGGER.info("Interrupted while waiting for available executors");
                Thread.currentThread().interrupt();
                break;
            }

            final int tasksToPoll = taskSemaphore.availablePermits();
            assert tasksToPoll > 0;

            LOGGER.debug("Polling up to %d tasks".formatted(tasksToPoll));
            final List<PolledWorkflowTaskRow> polledTasks;
            final Timer.Sample pollTimerSample = Timer.start();
            try {
                polledTasks = inJdbiTransaction(
                        handle -> new WorkflowDao(handle).pollTasks(taskQueueName, tasksToPoll));

                DistributionSummary
                        .builder("dtrack.workflow.task.dispatcher.poll.tasks")
                        .tag("taskRunner", taskRunner.getClass().getSimpleName())
                        .tag("taskQueue", taskQueueName)
                        .register(Metrics.getRegistry())
                        .record(polledTasks.size());
            } finally {
                pollTimerSample.stop(Timer
                        .builder("dtrack.workflow.task.dispatcher.poll.latency")
                        .tag("taskRunner", taskRunner.getClass().getSimpleName())
                        .tag("taskQueue", taskQueueName)
                        .register(Metrics.getRegistry()));
            }
            if (polledTasks.isEmpty()) {
                final long backoffMs = POLL_BACKOFF_INTERVAL_FUNCTION.apply(++pollsWithoutResults);
                LOGGER.debug("Backing off for %dms".formatted(backoffMs));
                try {
                    //noinspection BusyWait
                    Thread.sleep(backoffMs);
                    continue;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.warn("Thread interrupted during poll backoff");
                    break;
                }
            }

            pollsWithoutResults = 0;

            // Prevent race conditions where the next dispatcher iteration acquires a semaphore
            // permit before the dispatched tasks acquired theirs.
            final var permitAcquiredLatch = new CountDownLatch(polledTasks.size());
            for (final PolledWorkflowTaskRow polledTask : polledTasks) {
                taskExecutor.execute(() -> executeTask(polledTask, permitAcquiredLatch));
            }

            try {
                permitAcquiredLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for task executors to start", e);
            }
        }
    }

    private void executeTask(final PolledWorkflowTaskRow polledTask, final CountDownLatch permitAcquiredLatch) {
        final Timer.Sample processingTimerSample = Timer.start();
        final C taskContext = taskContextFactory.apply(polledTask);
        try (var ignoredMdcRunId = MDC.putCloseable(MDC_WORKFLOW_RUN_ID, String.valueOf(polledTask.workflowRunId()));
             var ignoredMdcCompletionId = MDC.putCloseable(MDC_WORKFLOW_COMPLETION_ID, String.valueOf(polledTask.completionId()));
             var ignoredMdcTaskId = MDC.putCloseable(MDC_WORKFLOW_TASK_ID, String.valueOf(polledTask.id()));
             var ignoredMdcTaskPriority = MDC.putCloseable(MDC_WORKFLOW_TASK_PRIORITY, String.valueOf(polledTask.priority()));
             var ignoredMdcTaskAttempts = MDC.putCloseable(MDC_WORKFLOW_TASK_ATTEMPT, String.valueOf(polledTask.attempt()));
             var ignoredMdcTaskQueue = MDC.putCloseable(MDC_WORKFLOW_TASK_QUEUE, taskQueueName);
             var ignoredMdcTaskRunner = MDC.putCloseable(MDC_WORKFLOW_TASK_RUNNER, taskRunner.getClass().getSimpleName())) {
            taskSemaphore.acquire();
            permitAcquiredLatch.countDown();

            taskContext.addToEventBuffer(engine.createTaskStartedEvent(polledTask));
            if (taskRunnerLogger.isDebugEnabled()) {
                taskRunnerLogger.debug("Processing");
            }

            final Optional<R> result = taskRunner.run(taskContext);
            final Optional<WorkflowPayload> resultPayload =
                    result.flatMap(taskResultConverter::convertToPayload);

            taskContext.addToEventBuffer(engine.createTaskCompletedEvent(polledTask, resultPayload.orElse(null)));

            if (taskRunnerLogger.isDebugEnabled()) {
                taskRunnerLogger.debug("Task completed");
            }
        } catch (WorkflowRunSuspendedException e) {
            taskContext.addToEventBuffer(
                    WorkflowEvent.newBuilder()
                            .setId(UUID.randomUUID().toString())
                            .setWorkflowRunId(polledTask.workflowRunId().toString())
                            .setTimestamp(Timestamps.now())
                            .setRunSuspended(WorkflowRunSuspended.newBuilder()
                                    .setTaskId(polledTask.id().toString())
                                    .setAttempt(polledTask.attempt())
                                    .addAllAwaitedCompletionIds(
                                            e.getAwaitedCompletionIds().stream()
                                                    .map(UUID::toString)
                                                    .toList())
                                    .build())
                            .build());

            if (taskRunnerLogger.isDebugEnabled()) {
                taskRunnerLogger.debug("Task suspended", e);
            }
        } catch (Throwable e) {
            taskContext.addToEventBuffer(engine.createTaskFailedEvent(polledTask, e));
            if (taskRunnerLogger.isDebugEnabled()) {
                taskRunnerLogger.debug("Task failed", e);
            }
        } finally {
            try {
                final List<WorkflowEvent> eventsToDispatch = taskContext.eventBuffer();
                LOGGER.debug("Dispatching %d buffered events".formatted(eventsToDispatch.size()));
                engine.dispatchEvents(eventsToDispatch).join();
            } catch (Throwable e) {
                LOGGER.error("Failed to dispatch events", e);
            }

            processingTimerSample.stop(Timer
                    .builder("dtrack.workflow.task.runner.process.latency")
                    .tag("taskRunner", taskRunner.getClass().getSimpleName())
                    .tag("taskQueue", taskQueueName)
                    .register(Metrics.getRegistry()));
            taskSemaphore.release();
        }
    }

}
