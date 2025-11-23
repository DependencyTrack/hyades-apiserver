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
    TaskSchedulerConfigMapping workflowTaskScheduler();

    @Valid
    TaskSchedulerConfigMapping activityTaskScheduler();

    Map<String, @Valid TaskWorkerConfigMapping> workflowTaskWorker();

    Map<String, @Valid TaskWorkerConfigMapping> activityTaskWorker();

    @Valid
    RetentionConfigMapping retention();

    @Valid
    BufferConfigMapping externalEventBuffer();

    @Valid
    BufferConfigMapping taskCommandBuffer();

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

    interface TaskSchedulerConfigMapping {

        @WithDefault("true")
        boolean enabled();

        @WithDefault("PT1S")
        Duration pollInterval();

    }

    interface TaskWorkerConfigMapping {

        @WithDefault("true")
        boolean enabled();

        @NotBlank
        String queueName();

        @Positive
        int maxConcurrency();

        @WithDefault("PT0.1S")
        Duration minPollInterval();

        @Valid
        BackoffConfigMapping pollBackoff();

    }

    interface RetentionConfigMapping {

        @WithDefault("true")
        boolean enabled();

        @WithDefault("1")
        @Positive
        int days();

    }

    interface BufferConfigMapping {

        @WithDefault("PT0.1S")
        Duration flushInterval();

        @WithDefault("100")
        @Positive
        int maxSize();

    }

    interface CacheConfigMapping {

        @WithDefault("PT5M")
        Duration ttl();

        @WithDefault("1000")
        @Positive
        int maxSize();

    }

    interface BackoffConfigMapping {

        @WithDefault("PT0.1S")
        Duration initialDelay();

        @WithDefault("1.5")
        @Positive
        double multiplier();

        @WithDefault("0.3")
        @Positive
        double randomizationFactor();

        @WithDefault("PT3S")
        Duration maxDelay();

        default IntervalFunction asIntervalFunction() {
            return IntervalFunction.ofExponentialRandomBackoff(
                    initialDelay(),
                    multiplier(),
                    randomizationFactor(),
                    maxDelay());
        }

    }

}
