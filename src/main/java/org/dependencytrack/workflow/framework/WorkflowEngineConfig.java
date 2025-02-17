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
package org.dependencytrack.workflow.framework;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Objects.requireNonNull;

public class WorkflowEngineConfig {

    public static class BufferConfig {

        private Duration flushInterval = Duration.ofMillis(5);
        private int maxBatchSize = 100;

        public Duration flushInterval() {
            return flushInterval;
        }

        public void setFlushInterval(final Duration flushInterval) {
            this.flushInterval = flushInterval;
        }

        public int maxBatchSize() {
            return maxBatchSize;
        }

        public void setMaxBatchSize(final int maxBatchSize) {
            this.maxBatchSize = maxBatchSize;
        }

    }

    public static class RetentionConfig {

        private int deletionBatchSize = 100;
        private Duration duration = Duration.ofDays(1);
        private Duration workerInitialDelay = Duration.ofMinutes(3);
        private Duration workerInterval = Duration.ofMinutes(5);

        public int deletionBatchSize() {
            return deletionBatchSize;
        }

        public void setDeletionBatchSize(final int deletionBatchSize) {
            this.deletionBatchSize = deletionBatchSize;
        }

        public Duration duration() {
            return duration;
        }

        public void setDuration(final Duration duration) {
            this.duration = duration;
        }

        public Duration workerInitialDelay() {
            return workerInitialDelay;
        }

        public void setWorkerInitialDelay(final Duration workerInitialDelay) {
            this.workerInitialDelay = workerInitialDelay;
        }

        public Duration workerInterval() {
            return workerInterval;
        }

        public void setWorkerInterval(final Duration workerInterval) {
            this.workerInterval = workerInterval;
        }

    }

    public static class SchedulerConfig {

        private Duration initialDelay = Duration.ofSeconds(15);
        private Duration pollInterval = Duration.ofSeconds(15);

        public Duration initialDelay() {
            return initialDelay;
        }

        public void setInitialDelay(final Duration initialDelay) {
            this.initialDelay = initialDelay;
        }

        public Duration pollInterval() {
            return pollInterval;
        }

        public void setPollInterval(final Duration pollInterval) {
            this.pollInterval = pollInterval;
        }

    }

    public static class TaskDispatcherConfig {

        private Duration minPollInterval = Duration.ofMillis(5);
        private IntervalFunction pollBackoffIntervalFunction = ofExponentialRandomBackoff(
                /* initialIntervalMillis */ 100,
                /* multiplier */ 2,
                /* randomizationFactor */ 0.3,
                /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(3));

        public Duration minPollInterval() {
            return minPollInterval;
        }

        public void setMinPollInterval(final Duration minPollInterval) {
            this.minPollInterval = minPollInterval;
        }

        public IntervalFunction pollBackoffIntervalFunction() {
            return pollBackoffIntervalFunction;
        }

        public void setPollBackoffIntervalFunction(final IntervalFunction pollBackoffIntervalFunction) {
            this.pollBackoffIntervalFunction = pollBackoffIntervalFunction;
        }

    }

    private final UUID instanceId;
    private final DataSource dataSource;
    private final BufferConfig externalEventBufferConfig = new BufferConfig();
    private final BufferConfig taskActionBufferConfig = new BufferConfig();
    private final RetentionConfig retentionConfig = new RetentionConfig();
    private final SchedulerConfig schedulerConfig = new SchedulerConfig();
    private final TaskDispatcherConfig workflowTaskDispatcherConfig = new TaskDispatcherConfig();
    private final TaskDispatcherConfig activityTaskDispatcherConfig = new TaskDispatcherConfig();
    private MeterRegistry meterRegistry;

    public WorkflowEngineConfig(final UUID instanceId, final DataSource dataSource) {
        this.instanceId = requireNonNull(instanceId, "instanceId must not be null");
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
    }

    public UUID instanceId() {
        return instanceId;
    }

    public DataSource dataSource() {
        return dataSource;
    }

    public BufferConfig externalEventBuffer() {
        return externalEventBufferConfig;
    }

    public BufferConfig taskActionBuffer() {
        return taskActionBufferConfig;
    }

    public RetentionConfig retention() {
        return retentionConfig;
    }

    public SchedulerConfig scheduler() {
        return schedulerConfig;
    }

    public TaskDispatcherConfig workflowTaskDispatcher() {
        return workflowTaskDispatcherConfig;
    }

    public TaskDispatcherConfig activityTaskDispatcher() {
        return activityTaskDispatcherConfig;
    }

    public MeterRegistry meterRegistry() {
        return meterRegistry;
    }

    public void setMeterRegistry(final MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

}
