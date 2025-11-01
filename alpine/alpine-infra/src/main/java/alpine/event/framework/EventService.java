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

import alpine.common.metrics.Metrics;
import alpine.common.util.ThreadUtil;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * A publish/subscribe (pub/sub) event service that provides the ability to publish events and
 * asynchronously inform all subscribers to subscribed events.
 *
 * This class will use a configurable number of worker threads when processing events.
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
        final var threadFactory = BasicThreadFactory.builder()
                .namingPattern(EXECUTOR_NAME + "-%d")
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();
        final int threadPoolSize = ThreadUtil.determineNumberOfWorkerThreads();
        final var executor = new ThreadPoolExecutor(
                threadPoolSize,
                threadPoolSize,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                threadFactory);
        INSTANCE = new EventService(executor);
        Metrics.registerExecutorService(executor, EXECUTOR_NAME);
    }

    private EventService(final ExecutorService executor) {
        super(executor);
    }

    public static EventService getInstance() {
        return INSTANCE;
    }

}
