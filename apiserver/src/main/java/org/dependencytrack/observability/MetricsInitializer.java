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
package org.dependencytrack.observability;

import io.github.mweirauch.micrometer.jvm.extras.ProcessMemoryMetrics;
import io.github.mweirauch.micrometer.jvm.extras.ProcessThreadMetrics;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmInfoMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.binder.system.UptimeMetrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.validation.constraints.NotNull;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * @since 5.7.0
 */
public final class MetricsInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricsInitializer.class);
    private static final Set<String> HISTOGRAM_METER_NAMES = Set.of(
            "alpine_event_processing",
            "dt.notification.router.rule.query.latency",
            "dt.notification.router.rule.filter.latency",
            "dt.notifications.emit.latency",
            "dt.outbox.relay.cycle.latency",
            "dt.outbox.relay.poll.latency",
            "dt.outbox.relay.send.latency",
            "pc.user.function.processing.time",
            "http.server.requests");

    private final Config config;
    private final MeterRegistry meterRegistry;

    MetricsInitializer(Config config, MeterRegistry meterRegistry) {
        this.config = config;
        this.meterRegistry = meterRegistry;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public MetricsInitializer() {
        this(ConfigProvider.getConfig(), Metrics.globalRegistry);
    }

    @Override
    public void contextInitialized(ServletContextEvent ignored) {
        final boolean metricsEnabled =
                config.getOptionalValue("dt.metrics.enabled", boolean.class)
                        .or(() -> config.getOptionalValue("alpine.metrics.enabled", boolean.class))
                        .orElse(false);
        if (!metricsEnabled) {
            return;
        }

        meterRegistry.config().meterFilter(new MeterFilter() {
            @Override
            public DistributionStatisticConfig configure(
                    @NotNull Meter.Id id,
                    @NotNull DistributionStatisticConfig config) {
                if (HISTOGRAM_METER_NAMES.contains(id.getName())) {
                    return DistributionStatisticConfig.builder()
                            .percentiles(/* none */) // Disable client-side calculation of percentiles.
                            .percentilesHistogram(true) // Publish histogram instead.
                            .build()
                            .merge(config);
                }

                return config;
            }
        });

        LOGGER.info("Registering system metrics");
        new ClassLoaderMetrics().bindTo(meterRegistry);
        new JvmGcMetrics().bindTo(meterRegistry);
        new JvmInfoMetrics().bindTo(meterRegistry);
        new JvmMemoryMetrics().bindTo(meterRegistry);
        new JvmThreadMetrics().bindTo(meterRegistry);
        new ProcessorMetrics().bindTo(meterRegistry);
        new ProcessMemoryMetrics().bindTo(meterRegistry);
        new ProcessThreadMetrics().bindTo(meterRegistry);
        new UptimeMetrics().bindTo(meterRegistry);
    }

}
