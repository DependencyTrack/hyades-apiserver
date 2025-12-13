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
package org.dependencytrack.dex.benchmark;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmInfoMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.metrics.exporter.pushgateway.PushGateway;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.DexEngineFactory;
import org.dependencytrack.dex.engine.api.TaskQueueType;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.migration.MigrationExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.ServiceLoader;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

public class BenchmarkApplication {

    private static final Logger LOGGER = LoggerFactory.getLogger(BenchmarkApplication.class);

    public static void main(String[] args) throws Exception {
        final PrometheusMeterRegistry meterRegistry = createMeterRegistry();
        final DataSource dataSource = createDataSource(meterRegistry);

        new MigrationExecutor(dataSource).execute();

        final var dexEngineConfig = new DexEngineConfig(dataSource);
        dexEngineConfig.taskEventBuffer().setMaxBatchSize(250);
        dexEngineConfig.taskEventBuffer().setFlushInterval(Duration.ofMillis(50));
        dexEngineConfig.setMeterRegistry(meterRegistry);

        final var dexEngineFactory = ServiceLoader.load(DexEngineFactory.class).findFirst().orElseThrow();

        final DexEngine dexEngine = dexEngineFactory.create(dexEngineConfig);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                dexEngine.close();
            } catch (IOException e) {
                LOGGER.error("Failed to shutdown dex engine", e);
            }
        }));

        dexEngine.registerWorkflow(
                new DummyWorkflow(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(30));
        dexEngine.registerActivity(
                new DummyActivity(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(30));

        dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.WORKFLOW, "default", 1000));
        dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "foo", 1000));
        dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "bar", 1000));
        dexEngine.createTaskQueue(new CreateTaskQueueRequest(TaskQueueType.ACTIVITY, "baz", 1000));

        dexEngine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("default", "default", 150));
        dexEngine.registerActivityWorker(new ActivityTaskWorkerOptions("foo-worker", "foo", 50));
        dexEngine.registerActivityWorker(new ActivityTaskWorkerOptions("bar-worker", "bar", 50));
        dexEngine.registerActivityWorker(new ActivityTaskWorkerOptions("baz-worker", "baz", 50));

        createWorkflowRuns(dexEngine, 250_000, 25_000);

        dexEngine.start();

        scheduleMetricsPublishing(meterRegistry);

        Thread.currentThread().join();
    }

    private static DataSource createDataSource(MeterRegistry meterRegistry) {
        final var hikariConfig = new HikariConfig();
        hikariConfig.setDriverClassName(org.postgresql.Driver.class.getName());
        hikariConfig.setJdbcUrl("jdbc:postgresql://localhost:5432/dex");
        hikariConfig.setUsername("dex");
        hikariConfig.setPassword("dex");
        hikariConfig.setMaximumPoolSize(10);
        hikariConfig.setMinimumIdle(5);
        hikariConfig.setMetricRegistry(meterRegistry);

        return new HikariDataSource(hikariConfig);
    }

    private static PrometheusMeterRegistry createMeterRegistry() {
        final var meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        new JvmInfoMetrics().bindTo(meterRegistry);
        new JvmGcMetrics().bindTo(meterRegistry);
        new JvmMemoryMetrics().bindTo(meterRegistry);

        meterRegistry.config().meterFilter(new MeterFilter() {
            @Override
            public DistributionStatisticConfig configure(
                    Meter.Id id,
                    DistributionStatisticConfig config) {
                if (id.getName().startsWith("dt.dex.")) {
                    return DistributionStatisticConfig.builder()
                            .percentilesHistogram(true)
                            .build()
                            .merge(config);
                }
                return config;
            }
        });

        return meterRegistry;
    }

    private static void createWorkflowRuns(DexEngine dexEngine, int total, int batchSize) {
        LOGGER.info("Creating {} workflow runs", total);

        for (int i = 0; i < total; i += batchSize) {
            final int currentBatchSize = Math.min(batchSize, total - batchSize);
            final var currentBatch = new ArrayList<CreateWorkflowRunRequest<?>>(currentBatchSize);

            for (int j = 0; j < currentBatchSize; j++) {
                currentBatch.add(new CreateWorkflowRunRequest<>(DummyWorkflow.class));
            }

            LOGGER.info("Creating batch of {} workflow runs", currentBatchSize);
            dexEngine.createRuns(currentBatch);
        }
    }

    private static void scheduleMetricsPublishing(PrometheusMeterRegistry meterRegistry) {
        final var pushGateway = PushGateway.builder()
                .registry(meterRegistry.getPrometheusRegistry())
                .address("localhost:9091")
                .build();

        final var pushExecutor = Executors.newSingleThreadScheduledExecutor();
        Runtime.getRuntime().addShutdownHook(new Thread(pushExecutor::close));

        pushExecutor.scheduleWithFixedDelay(
                () -> {
                    try {
                        pushGateway.push();
                    } catch (IOException e) {
                        LOGGER.warn("Failed to push metrics", e);
                    }
                },
                3_000,
                15_000,
                TimeUnit.MILLISECONDS);
    }

}
