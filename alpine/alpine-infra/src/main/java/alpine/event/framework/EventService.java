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
package alpine.event.framework;

import alpine.common.util.ThreadUtil;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * A publish/subscribe (pub/sub) event service that provides the ability to publish events and
 * asynchronously inform all subscribers to subscribed events.
 *
 * This class will use virtual threads with a semaphore-based concurrency limit
 * when processing events.
 *
 * @see alpine.Config.AlpineKey#WORKER_THREADS
 * @see alpine.Config.AlpineKey#WORKER_THREAD_MULTIPLIER
 * @see ThreadUtil#determineNumberOfWorkerThreads()
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class EventService extends BaseEventService {

    private static final EventService INSTANCE;
    private static final String EXECUTOR_NAME = "Alpine-EventService";

    static {
        final ExecutorConfig config = createExecutorConfig();
        INSTANCE = new EventService(config.executor(), config.semaphore());
        new ExecutorServiceMetrics(INSTANCE.getExecutor(), EXECUTOR_NAME, null)
                .bindTo(Metrics.globalRegistry);
    }

    private EventService(ExecutorService executor, Semaphore semaphore) {
        super(executor, semaphore);
    }

    public static EventService getInstance() {
        return INSTANCE;
    }

    @Override
    ExecutorConfig executorConfig() {
        return createExecutorConfig();
    }

    private static ExecutorConfig createExecutorConfig() {
        final ExecutorService executor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .name(EXECUTOR_NAME + "-", 0)
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .factory());
        final var semaphore = new Semaphore(ThreadUtil.determineNumberOfWorkerThreads());
        return new ExecutorConfig(executor, semaphore);
    }

}
