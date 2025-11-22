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
package org.dependencytrack.dex.engine.api;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.common.pagination.PageTokenEncoder;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Objects.requireNonNull;

public class DexEngineConfig {

    public static class BufferConfig {

        private Duration flushInterval = Duration.ofMillis(5);
        private int maxBatchSize = 100;

        private BufferConfig() {
        }

        /**
         * @return Interval at which the buffer content is flushed.
         */
        public Duration flushInterval() {
            return flushInterval;
        }

        public void setFlushInterval(final Duration flushInterval) {
            this.flushInterval = flushInterval;
        }

        /**
         * @return Maximum batch size of items to flush at once.
         */
        public int maxBatchSize() {
            return maxBatchSize;
        }

        public void setMaxBatchSize(final int maxBatchSize) {
            this.maxBatchSize = maxBatchSize;
        }

    }

    public static class CacheConfig {

        private Duration evictAfterAccess = Duration.ofMinutes(5);
        private int maxSize = 1000;

        private CacheConfig() {
        }

        public Duration evictAfterAccess() {
            return evictAfterAccess;
        }

        public void setEvictAfterAccess(Duration evictAfterAccess) {
            this.evictAfterAccess = evictAfterAccess;
        }

        public int maxSize() {
            return maxSize;
        }

        public void setMaxSize(int maxSize) {
            this.maxSize = maxSize;
        }

    }

    public static class RetentionConfig {

        private int days = 3;
        private boolean workerEnabled = true;
        private Duration workerInitialDelay = Duration.ofMinutes(1);
        private Duration workerInterval = Duration.ofMinutes(30);

        private RetentionConfig() {
        }

        /**
         * @return Number of days to retain completed workflow runs for.
         */
        public int days() {
            return days;
        }

        public void setDays(final int days) {
            this.days = days;
        }

        /**
         * @return Whether the retention worker shall be enabled in this instance.
         */
        public boolean isWorkerEnabled() {
            return workerEnabled;
        }

        public void setWorkerEnabled(final boolean workerEnabled) {
            this.workerEnabled = workerEnabled;
        }

        /**
         * @return Initial delay before the retention worker first runs.
         */
        public Duration workerInitialDelay() {
            return workerInitialDelay;
        }

        public void setWorkerInitialDelay(final Duration workerInitialDelay) {
            this.workerInitialDelay = workerInitialDelay;
        }

        /**
         * @return Interval at which the retention worker will run.
         */
        public Duration workerInterval() {
            return workerInterval;
        }

        public void setWorkerInterval(final Duration workerInterval) {
            this.workerInterval = workerInterval;
        }

    }

    public static class TaskSchedulerConfig {

        private boolean enabled = true;
        private Duration pollInterval = Duration.ofMillis(100);

        private TaskSchedulerConfig() {
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(final boolean enabled) {
            this.enabled = enabled;
        }

        public Duration pollInterval() {
            return pollInterval;
        }

        public void setPollInterval(final Duration pollInterval) {
            this.pollInterval = pollInterval;
        }

    }

    public static class TaskWorkerConfig {

        private Duration minPollInterval = Duration.ofMillis(5);
        private IntervalFunction pollBackoffIntervalFunction = ofExponentialRandomBackoff(
                /* initialIntervalMillis */ 100,
                /* multiplier */ 2,
                /* randomizationFactor */ 0.3,
                /* maxIntervalMillis */ TimeUnit.SECONDS.toMillis(3));

        private TaskWorkerConfig() {
        }

        /**
         * @return Minimum interval at which tasks are being polled.
         */
        public Duration minPollInterval() {
            return minPollInterval;
        }

        public void setMinPollInterval(final Duration minPollInterval) {
            this.minPollInterval = minPollInterval;
        }

        /**
         * @return Interval function to use for poll backoff.
         */
        public IntervalFunction pollBackoffIntervalFunction() {
            return pollBackoffIntervalFunction;
        }

        public void setPollBackoffIntervalFunction(final IntervalFunction pollBackoffIntervalFunction) {
            this.pollBackoffIntervalFunction = pollBackoffIntervalFunction;
        }

    }

    private final UUID instanceId;
    private final DataSource dataSource;
    private final CacheConfig runHistoryCache = new CacheConfig();
    private final BufferConfig externalEventBufferConfig = new BufferConfig();
    private final BufferConfig taskCommandBufferConfig = new BufferConfig();
    private final RetentionConfig retentionConfig = new RetentionConfig();
    private final TaskSchedulerConfig workflowTaskSchedulerConfig = new TaskSchedulerConfig();
    private final TaskSchedulerConfig activityTaskSchedulerConfig = new TaskSchedulerConfig();
    private final TaskWorkerConfig activityTaskWorkerConfig = new TaskWorkerConfig();

    private MeterRegistry meterRegistry = new SimpleMeterRegistry();
    private PageTokenEncoder pageTokenEncoder = new SimplePageTokenEncoder();

    public DexEngineConfig(final UUID instanceId, final DataSource dataSource) {
        this.instanceId = requireNonNull(instanceId, "instanceId must not be null");
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
    }

    /**
     * @return ID that uniquely identifies this instance of the engine.
     */
    public UUID instanceId() {
        return instanceId;
    }

    /**
     * @return {@link DataSource} to use for persistence.
     */
    public DataSource dataSource() {
        return dataSource;
    }

    public CacheConfig runHistoryCache() {
        return runHistoryCache;
    }

    /**
     * @return Config for the buffer of external events.
     */
    public BufferConfig externalEventBuffer() {
        return externalEventBufferConfig;
    }

    /**
     * @return Config for the buffer of task commands.
     */
    public BufferConfig taskCommandBuffer() {
        return taskCommandBufferConfig;
    }

    /**
     * @return Config for workflow run retention.
     */
    public RetentionConfig retention() {
        return retentionConfig;
    }

    public TaskSchedulerConfig workflowTaskScheduler() {
        return workflowTaskSchedulerConfig;
    }

    public TaskSchedulerConfig activityTaskScheduler() {
        return activityTaskSchedulerConfig;
    }

    public TaskWorkerConfig activityTaskWorker() {
        return activityTaskWorkerConfig;
    }

    public TaskWorkerConfig workflowTaskWorker() {
        return activityTaskWorkerConfig;
    }

    /**
     * @return {@link MeterRegistry} to bind metrics to.
     */
    public MeterRegistry meterRegistry() {
        return meterRegistry;
    }

    public void setMeterRegistry(final MeterRegistry meterRegistry) {
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
    }

    public PageTokenEncoder pageTokenEncoder() {
        return pageTokenEncoder;
    }

    public void setPageTokenEncoder(final PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = requireNonNull(pageTokenEncoder, "pageTokenEncoder must not be null");
    }

}
