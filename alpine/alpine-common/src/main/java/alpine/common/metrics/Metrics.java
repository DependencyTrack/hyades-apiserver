/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.common.metrics;

import alpine.Config;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;

/**
 * @since 2.1.0
 */
public final class Metrics {

    private static final PrometheusMeterRegistry PROMETHEUS_METER_REGISTRY;

    static {
        customize(io.micrometer.core.instrument.Metrics.globalRegistry);

        PROMETHEUS_METER_REGISTRY = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        // Add to the global meter registry, so application code can
        // simply refer to io.micrometer.core.instrument.Metrics.globalRegistry.
        io.micrometer.core.instrument.Metrics.addRegistry(PROMETHEUS_METER_REGISTRY);
    }

    public static PrometheusMeterRegistry getPrometheusMeterRegistry() {
        return PROMETHEUS_METER_REGISTRY;
    }

    public static void registerExecutorService(final ExecutorService executorService, final String name) {
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            new ExecutorServiceMetrics(executorService, name, null).bindTo(PROMETHEUS_METER_REGISTRY);
        }
    }

    static void customize(final MeterRegistry meterRegistry) {
        for (final MeterRegistryCustomizer customizer : ServiceLoader.load(MeterRegistryCustomizer.class)) {
            customizer.accept(meterRegistry);
        }
    }

}
