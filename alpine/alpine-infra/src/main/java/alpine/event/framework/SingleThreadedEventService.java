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

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A publish/subscribe (pub/sub) event service that provides the ability to publish events and
 * asynchronously inform all subscribers to subscribed events.
 *
 * This class will use a single thread for the processing of events.
 *
 * Use EventService for an implementation that allows for a configurable number of threads.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public final class SingleThreadedEventService extends BaseEventService {

    private static final SingleThreadedEventService INSTANCE;
    private static final String EXECUTOR_NAME = "Alpine-SingleThreadedEventService";

    static {
        final ExecutorConfig config = createExecutorConfig();
        INSTANCE = new SingleThreadedEventService(config.executor());
        new ExecutorServiceMetrics(INSTANCE.getExecutor(), EXECUTOR_NAME, null)
                .bindTo(Metrics.globalRegistry);
    }

    private SingleThreadedEventService(ExecutorService executor) {
        super(executor, null);
    }

    public static SingleThreadedEventService getInstance() {
        return INSTANCE;
    }

    @Override
    ExecutorConfig executorConfig() {
        return createExecutorConfig();
    }

    private static ExecutorConfig createExecutorConfig() {
        final var threadFactory = BasicThreadFactory.builder()
                .namingPattern(EXECUTOR_NAME)
                .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                .build();
        return new ExecutorConfig(Executors.newFixedThreadPool(1, threadFactory), null);
    }

}
