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
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.UUID;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Objects.requireNonNull;

public class DexEngineConfig {

    public static class BufferConfig {

        private Duration flushInterval = Duration.ofMillis(100);
        private int maxBatchSize = 100;

        private BufferConfig() {
        }

        /**
         * @return Interval at which the buffer content is flushed.
         */
        public Duration flushInterval() {
            return flushInterval;
        }

        public void setFlushInterval(Duration flushInterval) {
            this.flushInterval = flushInterval;
        }

        /**
         * @return Maximum batch size of items to flush at once.
         */
        public int maxBatchSize() {
            return maxBatchSize;
        }

        public void setMaxBatchSize(int maxBatchSize) {
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

    public static class LeaderElectionConfig {

        private Duration leaseDuration = Duration.ofSeconds(30);
        private Duration leaseCheckInterval = Duration.ofSeconds(15);

        private LeaderElectionConfig() {
        }

        /**
         * @return The duration for which leadership leases are valid for.
         */
        public Duration leaseDuration() {
            return leaseDuration;
        }

        public void setLeaseDuration(Duration leaseDuration) {
            this.leaseDuration = leaseDuration;
        }

        /**
         * @return The interval at which leadership leases will be checked for.
         */
        public Duration leaseCheckInterval() {
            return leaseCheckInterval;
        }

        public void setLeaseCheckInterval(Duration leaseCheckInterval) {
            this.leaseCheckInterval = leaseCheckInterval;
        }

    }

    public static class RetentionConfig {

        private Duration duration = Duration.ofDays(1);
        private boolean workerEnabled = true;
        private Duration workerInitialDelay = Duration.ofMinutes(1);
        private Duration workerInterval = Duration.ofMinutes(30);

        private RetentionConfig() {
        }

        /**
         * @return Duration to retain completed workflow runs for.
         */
        public Duration duration() {
            return duration;
        }

        public void setDuration(Duration duration) {
            this.duration = duration;
        }

        /**
         * @return Whether the retention worker shall be enabled in this instance.
         */
        public boolean isWorkerEnabled() {
            return workerEnabled;
        }

        public void setWorkerEnabled(boolean workerEnabled) {
            this.workerEnabled = workerEnabled;
        }

        /**
         * @return Initial delay before the retention worker first runs.
         */
        public Duration workerInitialDelay() {
            return workerInitialDelay;
        }

        public void setWorkerInitialDelay(Duration workerInitialDelay) {
            this.workerInitialDelay = workerInitialDelay;
        }

        /**
         * @return Interval at which the retention worker will run.
         */
        public Duration workerInterval() {
            return workerInterval;
        }

        public void setWorkerInterval(Duration workerInterval) {
            this.workerInterval = workerInterval;
        }

    }

    public static class TaskSchedulerConfig {

        private boolean enabled = true;
        private Duration pollInterval = Duration.ofMillis(100);
        private IntervalFunction pollBackoffFunction = ofExponentialRandomBackoff(100L, 2.0, 0.3, 3000L);

        private TaskSchedulerConfig() {
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration pollInterval() {
            return pollInterval;
        }

        public void setPollInterval(Duration pollInterval) {
            this.pollInterval = pollInterval;
        }

        public IntervalFunction pollBackoffFunction() {
            return pollBackoffFunction;
        }

        public void setPollBackoffFunction(IntervalFunction pollBackoffFunction) {
            this.pollBackoffFunction = pollBackoffFunction;
        }

    }

    private final String instanceId;
    private final DataSource dataSource;
    private final LeaderElectionConfig leaderElectionConfig = new LeaderElectionConfig();
    private final CacheConfig runHistoryCacheConfig = new CacheConfig();
    private final BufferConfig externalEventBufferConfig = new BufferConfig();
    private final BufferConfig taskEventsBufferConfig = new BufferConfig();
    private final BufferConfig activityTaskHeartbeatBufferConfig = new BufferConfig();
    private final RetentionConfig retentionConfig = new RetentionConfig();
    private final TaskSchedulerConfig workflowTaskSchedulerConfig = new TaskSchedulerConfig();
    private final TaskSchedulerConfig activityTaskSchedulerConfig = new TaskSchedulerConfig();

    private MeterRegistry meterRegistry = new SimpleMeterRegistry();
    private PageTokenEncoder pageTokenEncoder = new SimplePageTokenEncoder();

    public DexEngineConfig(DataSource dataSource) {
        this.instanceId = generateInstanceId();
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
    }

    /**
     * @return ID that uniquely identifies this instance of the engine.
     */
    public String instanceId() {
        return instanceId;
    }

    /**
     * @return {@link DataSource} to use for persistence.
     */
    public DataSource dataSource() {
        return dataSource;
    }

    public LeaderElectionConfig leaderElection() {
        return leaderElectionConfig;
    }

    public CacheConfig runHistoryCache() {
        return runHistoryCacheConfig;
    }

    /**
     * @return Config for the buffer of external events.
     */
    public BufferConfig externalEventBuffer() {
        return externalEventBufferConfig;
    }

    /**
     * @return Config for the buffer of task events.
     */
    public BufferConfig taskEventBuffer() {
        return taskEventsBufferConfig;
    }

    public BufferConfig activityTaskHeartbeatBuffer() {
        return activityTaskHeartbeatBufferConfig;
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

    /**
     * @return {@link MeterRegistry} to bind metrics to.
     */
    public MeterRegistry meterRegistry() {
        return meterRegistry;
    }

    public void setMeterRegistry(MeterRegistry meterRegistry) {
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
    }

    public PageTokenEncoder pageTokenEncoder() {
        return pageTokenEncoder;
    }

    public void setPageTokenEncoder(PageTokenEncoder pageTokenEncoder) {
        this.pageTokenEncoder = requireNonNull(pageTokenEncoder, "pageTokenEncoder must not be null");
    }

    private static String generateInstanceId() {
        final String hostName;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            throw new UncheckedIOException(e);
        }

        return "%s-%s".formatted(hostName, UUID.randomUUID().toString().substring(0, 8));
    }

}
