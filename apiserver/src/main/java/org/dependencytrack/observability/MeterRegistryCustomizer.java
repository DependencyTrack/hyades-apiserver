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
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import jakarta.validation.constraints.NotNull;

public class MeterRegistryCustomizer implements alpine.common.metrics.MeterRegistryCustomizer {

    @Override
    public void accept(final MeterRegistry meterRegistry) {
        new ProcessMemoryMetrics().bindTo(meterRegistry);
        new ProcessThreadMetrics().bindTo(meterRegistry);

        meterRegistry.config().meterFilter(new PercentilesHistogramMeterFilter());
    }

    private static final class PercentilesHistogramMeterFilter implements MeterFilter {

        @Override
        public DistributionStatisticConfig configure(@NotNull final Meter.Id id,
                                                     @NotNull final DistributionStatisticConfig config) {
            if ("alpine_event_processing".equals(id.getName())
                    || "pc.user.function.processing.time".equals(id.getName())
                    || "http.server.requests".equals(id.getName())) {
                return DistributionStatisticConfig.builder()
                        .percentiles(/* none */) // Disable client-side calculation of percentiles.
                        .percentilesHistogram(true) // Publish histogram instead.
                        .build()
                        .merge(config);
            }

            return config;
        }

    }

}
