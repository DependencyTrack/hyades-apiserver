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

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;

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

    private UUID instanceId = UUID.randomUUID();
    private final BufferConfig externalEventBufferConfig = new BufferConfig();
    private final BufferConfig taskActionBufferConfig = new BufferConfig();
    private final TaskDispatcherConfig taskDispatcherConfig = new TaskDispatcherConfig();
    private MeterRegistry meterRegistry;

    public UUID instanceId() {
        return instanceId;
    }

    public void setInstanceId(final UUID instanceId) {
        this.instanceId = instanceId;
    }

    public BufferConfig externalEventBuffer() {
        return externalEventBufferConfig;
    }

    public BufferConfig taskActionBuffer() {
        return taskActionBufferConfig;
    }

    public TaskDispatcherConfig taskDispatcher() {
        return taskDispatcherConfig;
    }

    public MeterRegistry meterRegistry() {
        return meterRegistry;
    }

    public void setMeterRegistry(final MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

}
