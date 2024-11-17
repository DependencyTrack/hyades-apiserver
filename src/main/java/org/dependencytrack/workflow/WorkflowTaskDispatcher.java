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

import alpine.common.metrics.Metrics;
import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.proto.workflow.v1alpha1.RunnerStarted;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

final class WorkflowTaskDispatcher<A, R> implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowTaskDispatcher.class);
    private static final IntervalFunction POLL_BACKOFF_INTERVAL_FUNCTION =
            IntervalFunction.ofExponentialRandomBackoff(
                    /* initialIntervalMillis */ 500,
                    /* multiplier */ 1.5,
                    /* randomizationFactor */ 0.3,
                    /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(5));

    private final WorkflowEngine engine;
    private final ExecutorService executorService;
    private final String workflowName;
    private final WorkflowRunner<A, R> workflowRunner;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final Semaphore taskSemaphore;

    WorkflowTaskDispatcher(
            final WorkflowEngine engine,
            final ExecutorService executorService,
            final String workflowName,
            final WorkflowRunner<A, R> workflowRunner,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final int maxConcurrency) {
        this.engine = engine;
        this.executorService = executorService;
        this.workflowName = workflowName;
        this.workflowRunner = workflowRunner;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.taskSemaphore = new Semaphore(maxConcurrency);
    }

    @Override
    public void run() {
        int pollsWithoutResults = 0;

        while (engine.state().isNotStoppingOrStopped() && !Thread.currentThread().isInterrupted()) {
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

            LOGGER.debug("Polling up to {} tasks", tasksToPoll);
            final List<WorkflowRunTask> polledTasks;
            final Timer.Sample pollTimerSample = Timer.start();
            try {
                polledTasks = engine.pollWorkflowRunTasks(workflowName, tasksToPoll);

                DistributionSummary
                        .builder("dtrack.workflow.task.dispatcher.poll.tasks")
                        .register(Metrics.getRegistry())
                        .record(polledTasks.size());
            } finally {
                pollTimerSample.stop(Timer
                        .builder("dtrack.workflow.task.dispatcher.poll.latency")
                        .register(Metrics.getRegistry()));
            }
            if (polledTasks.isEmpty()) {
                final long backoffMs = POLL_BACKOFF_INTERVAL_FUNCTION.apply(++pollsWithoutResults);
                LOGGER.debug("Backing off for {}ms", backoffMs);
                try {
                    //noinspection BusyWait
                    Thread.sleep(backoffMs);
                    continue;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.warn("Thread interrupted during poll backoff", e);
                    break;
                }
            }

            pollsWithoutResults = 0;

            // Prevent race conditions where the next dispatcher iteration acquires a semaphore
            // permit before the dispatched tasks acquired theirs.
            final var permitAcquiredLatch = new CountDownLatch(polledTasks.size());
            for (final WorkflowRunTask polledTask : polledTasks) {
                executorService.execute(() -> executeTask(polledTask, permitAcquiredLatch));
            }

            try {
                permitAcquiredLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.warn("Interrupted while waiting for task executors to start", e);
            }
        }
    }

    private void executeTask(final WorkflowRunTask polledTask, final CountDownLatch permitAcquiredLatch) {
        try {
            taskSemaphore.acquire();
            permitAcquiredLatch.countDown();

            final var workflowRun = new WorkflowRun(
                    polledTask.workflowRunId(),
                    polledTask.workflowName(),
                    polledTask.workflowVersion(),
                    polledTask.eventLog());
            workflowRun.onEvent(WorkflowEvent.newBuilder()
                    .setSequenceId(-1)
                    .setTimestamp(Timestamps.now())
                    .setRunnerStarted(RunnerStarted.newBuilder().build())
                    .build());

            int eventsAdded = 0;
            for (final WorkflowEvent newEvent : polledTask.inboxEvents()) {
                workflowRun.onEvent(newEvent);
                eventsAdded++;

                if (newEvent.hasRunStarted()) {
                    LOGGER.info("Starting run of workflow {} with ID {}",
                            newEvent.getRunStarted().getWorkflowName(), polledTask.workflowRunId());
                }
            }

            if (eventsAdded == 0) {
                LOGGER.warn("No new events");
                return;
            }

            final var ctx = new WorkflowRunContext<>(
                    polledTask.workflowRunId(),
                    polledTask.workflowName(),
                    polledTask.workflowVersion(),
                    polledTask.priority(),
                    argumentConverter.convertFromPayload(polledTask.argument()),
                    workflowRunner,
                    resultConverter,
                    workflowRun.eventLog(),
                    workflowRun.inboxEvents());
            final List<WorkflowCommand> commands = ctx.runWorkflow();

            workflowRun.executeCommands(commands);

            // TODO: Send this off to Kafka and do the sync in batches
            //  to take load off the database.
            engine.completeWorkflowRunTask(workflowRun);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while waiting for semaphore permit", e);
            engine.abandonWorkflowRunTask(polledTask);
        } catch (Throwable e) {
            LOGGER.error("failed", e);
        } finally {
            taskSemaphore.release();
        }
    }

}