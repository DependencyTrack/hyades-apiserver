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
package org.dependencytrack.tasks;

import alpine.Config;
import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.Subscriber;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.time.Duration;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class TaskSchedulerTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private static final Queue<Event> EVENTS = new ConcurrentLinkedQueue<>();

    public static class TestSubscriber implements Subscriber {

        @Override
        public void inform(final Event event) {
            EVENTS.add(event);
        }

    }

    @BeforeClass
    public static void setUpClass() {
        Config.enableUnitTests();

        EventService.getInstance().subscribe(PortfolioMetricsUpdateEvent.class, TestSubscriber.class);
    }

    @AfterClass
    public static void tearDownClass() {
        EventService.getInstance().unsubscribe(TestSubscriber.class);
    }

    @Before
    public void before() throws Exception {
        environmentVariables.set("TASK_PORTFOLIO_METRICS_UPDATE_CRON", "* * * * * *");
        environmentVariables.set("TASK_SCHEDULER_INITIAL_DELAY", "5");
        environmentVariables.set("TASK_SCHEDULER_POLLING_INTERVAL", "1000");

        super.before();

        // Force initialization of TaskScheduler.
        final var ignored = TaskScheduler.getInstance();
    }

    @After
    public void after() {
        TaskScheduler.getInstance().shutdown();
        EVENTS.clear();

        super.after();
    }

    @Test
    public void test() throws Exception {
        await("Event Dispatch")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(EVENTS).hasSize(1));
    }

}