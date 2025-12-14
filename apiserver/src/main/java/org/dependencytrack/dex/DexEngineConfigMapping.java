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
package org.dependencytrack.dex;

import io.github.resilience4j.core.IntervalFunction;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * @since 5.7.0
 */
@ConfigMapping(prefix = "dt.dex-engine")
public interface DexEngineConfigMapping {

    @WithDefault("false")
    boolean enabled();

    @Valid
    @WithName("datasource")
    DataSourceConfigMapping dataSource();

    @Valid
    MigrationConfigMapping migration();

    @Valid
    LeaderElectionConfigMapping leaderElection();

    @Valid
    TaskSchedulerConfigMapping workflowTaskScheduler();

    @Valid
    TaskSchedulerConfigMapping activityTaskScheduler();

    Map<String, @Valid TaskWorkerConfigMapping> workflowTaskWorker();

    Map<String, @Valid TaskWorkerConfigMapping> activityTaskWorker();

    @Valid
    MaintenanceConfigMapping maintenance();

    @Valid
    BufferConfigMapping externalEventBuffer();

    @Valid
    BufferConfigMapping taskEventBuffer();

    @Valid
    BufferConfigMapping activityTaskHeartbeatBuffer();

    @Valid
    CacheConfigMapping runHistoryCache();

    interface DataSourceConfigMapping {

        @WithDefault("default")
        @NotBlank
        String name();

    }

    interface MigrationConfigMapping {

        @WithName("datasource.name")
        Optional<String> dataSourceName();

    }

    interface LeaderElectionConfigMapping {

        @WithName("lease-duration-ms")
        @WithDefault("30000")
        @Positive
        long leaseDurationMillis();

        @WithName("lease-check-interval-ms")
        @WithDefault("15000")
        @Positive
        long leaseCheckIntervalMillis();

    }

    interface TaskSchedulerConfigMapping {

        @WithName("poll-interval-ms")
        @WithDefault("100")
        @Positive
        long pollIntervalMillis();

        @Valid
        BackoffConfigMapping pollBackoff();

    }

    interface TaskWorkerConfigMapping {

        @WithDefault("true")
        boolean enabled();

        @NotBlank
        String queueName();

        @Positive
        int maxConcurrency();

        @WithName("min-poll-interval-ms")
        @WithDefault("100")
        long minPollIntervalMillis();

        @Valid
        BackoffConfigMapping pollBackoff();

    }

    interface MaintenanceConfigMapping {

        @WithDefault("P1D")
        @Positive
        Duration runRetentionDuration();

        @WithDefault("1000")
        @Positive
        int runDeletionBatchSize();

        @WithName("worker-initial-delay-ms")
        @WithDefault("60000")
        @Positive
        long workerInitialDelayMillis();

        @WithName("worker-interval-ms")
        @WithDefault("900000")
        @Positive
        long workerIntervalMillis();

    }

    interface BufferConfigMapping {

        @WithName("flush-interval-ms")
        @WithDefault("100")
        @Positive
        long flushIntervalMillis();

        @WithDefault("100")
        @Positive
        int maxSize();

    }

    interface CacheConfigMapping {

        @WithName("ttl-ms")
        @WithDefault("300000")
        @Positive
        long ttlMillis();

        @WithDefault("1000")
        @Positive
        int maxSize();

    }

    interface BackoffConfigMapping {

        @WithName("initial-delay-ms")
        @WithDefault("100")
        @Positive
        long initialDelayMillis();

        @WithDefault("1.5")
        @Positive
        double multiplier();

        @WithDefault("0.3")
        @Positive
        double randomizationFactor();

        @WithName("max-delay-ms")
        @WithDefault("3000")
        @Positive
        long maxDelayMillis();

        default IntervalFunction asIntervalFunction() {
            return IntervalFunction.ofExponentialRandomBackoff(
                    initialDelayMillis(),
                    multiplier(),
                    randomizationFactor(),
                    maxDelayMillis());
        }

    }

}
