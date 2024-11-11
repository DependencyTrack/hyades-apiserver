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
import alpine.event.framework.LoggableUncaughtExceptionHandler;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.dependencytrack.workflow.persistence.PolledWorkflowTaskRow;
import org.dependencytrack.workflow.persistence.WorkflowDao;
import org.slf4j.MDC;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_ACTIVITY_RUN_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_RUN_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_ATTEMPT;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_ID;
import static org.dependencytrack.common.MdcKeys.MDC_WORKFLOW_TASK_PRIORITY;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

final class VirtualThreadWorkflowTaskCoordinator<A, R, C extends WorkflowTaskContext<A>> implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(WorkflowTaskCoordinator.class);
    private static final IntervalFunction POLL_BACKOFF_INTERVAL_FUNCTION =
            IntervalFunction.ofExponentialRandomBackoff(
                    /* initialIntervalMillis */ 500,
                    /* multiplier */ 1.5,
                    /* randomizationFactor */ 0.3,
                    /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(5));

    private final WorkflowEngine workflowEngine;
    private final WorkflowTaskRunner<A, R, C> taskRunner;
    private final WorkflowTaskContext.Factory<A, C> contextFactory;
    private final PayloadConverter<R> resultConverter;
    private final String queue;
    private final Logger logger;
    private final Semaphore taskSemaphore;
    private final ExecutorService taskExecutor;

    VirtualThreadWorkflowTaskCoordinator(
            final WorkflowEngine workflowEngine,
            final WorkflowTaskRunner<A, R, C> taskRunner,
            final WorkflowTaskContext.Factory<A, C> contextFactory,
            final PayloadConverter<R> resultConverter,
            final int maxConcurrency,
            final String queue) {
        this.workflowEngine = workflowEngine;
        this.taskRunner = taskRunner;
        this.contextFactory = contextFactory;
        this.resultConverter = resultConverter;
        this.queue = queue;
        this.logger = Logger.getLogger(taskRunner.getClass());
        this.taskSemaphore = new Semaphore(maxConcurrency);
        this.taskExecutor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual()
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .name("WorkflowEngine-WorkflowRunner-" + queue + "-")
                .factory());
    }

    @Override
    public void run() {
        int pollMisses = 0;
        while (workflowEngine.state().isNotStoppingOrStopped()) {
            final int tasksToPoll = taskSemaphore.availablePermits();
            if (tasksToPoll == 0) {
                continue;
            }

            final List<PolledWorkflowTaskRow> polledTasks;
            final Timer.Sample pollTimerSample = Timer.start();
            try {
                // TODO: Add retries & circuit breaker?
                polledTasks = inJdbiTransaction(handle -> new WorkflowDao(handle).pollTasks(queue, tasksToPoll));
            } finally {
                pollTimerSample.stop(Timer
                        .builder("dtrack.workflow.task.worker.poll.latency")
                        .tag("queue", queue)
                        .register(Metrics.getRegistry()));
            }
            if (polledTasks.isEmpty()) {
                final long backoffMs = POLL_BACKOFF_INTERVAL_FUNCTION.apply(++pollMisses);
                logger.debug("Backing off for %dms".formatted(backoffMs));
                try {
                    Thread.sleep(backoffMs);
                    continue;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(e);
                }
            }

            pollMisses = 0;

            for (final PolledWorkflowTaskRow polledTask : polledTasks) {
                taskExecutor.execute(() -> executeTask(polledTask));
            }
        }

        taskExecutor.shutdown();
        try {
            logger.info("Waiting for task processing to complete");
            taskExecutor.awaitTermination(Integer.MAX_VALUE, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for tasks to complete", e);
        }
    }

    private void executeTask(final PolledWorkflowTaskRow polledTask) {
        final Timer.Sample processingTimerSample = Timer.start();
        try (var ignoredMdcRunId = MDC.putCloseable(MDC_WORKFLOW_RUN_ID, String.valueOf(polledTask.workflowRunId()));
             var ignoredMdcActivityRunId = MDC.putCloseable(MDC_WORKFLOW_ACTIVITY_RUN_ID, String.valueOf(polledTask.activityRunId()));
             var ignoredMdcTaskId = MDC.putCloseable(MDC_WORKFLOW_TASK_ID, String.valueOf(polledTask.id()));
             var ignoredMdcTaskPriority = MDC.putCloseable(MDC_WORKFLOW_TASK_PRIORITY, String.valueOf(polledTask.priority()));
             var ignoredMdcTaskAttempts = MDC.putCloseable(MDC_WORKFLOW_TASK_ATTEMPT, String.valueOf(polledTask.attempt()))) {
            taskSemaphore.acquire();

            workflowEngine.dispatchTaskStartedEvent(polledTask) /* .join() */;

            if (LOGGER.isDebugEnabled()) {
                logger.debug("Processing");
            }

            final C context = contextFactory.apply(polledTask);
            final Optional<R> result = taskRunner.run(context);

            workflowEngine.dispatchTaskCompletedEvent(polledTask,
                    result.flatMap(resultConverter::convertToPayload).orElse(null));
            if (LOGGER.isDebugEnabled()) {
                logger.debug("Task completed");
            }
        } catch (WorkflowRunSuspendedException e) {
            if (e.getActivityCompletedResumeCondition() != null) {
                workflowEngine.dispatchTaskSuspendedEvent(
                        polledTask, e.getActivityCompletedResumeCondition()) /* .join() */;
            } else if (e.getExternalEventResumeCondition() != null) {
                workflowEngine.dispatchTaskSuspendedEvent(
                        polledTask, e.getExternalEventResumeCondition()) /* .join() */;
            } else {
                throw new IllegalStateException("No resume condition provided", e);
            }

            if (LOGGER.isDebugEnabled()) {
                logger.debug("Task suspended", e);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Task interrupted", e);
        } catch (Exception | AssertionError e) {
            workflowEngine.dispatchTaskFailedEvent(polledTask, e) /* .join() */;
            if (LOGGER.isDebugEnabled()) {
                logger.debug("Task failed", e);
            }
        } finally {
            taskSemaphore.release();
            processingTimerSample.stop(Timer
                    .builder("dtrack.workflow.task.worker.process.latency")
                    .tag("queue", queue)
                    .register(Metrics.getRegistry()));
        }
    }

}
