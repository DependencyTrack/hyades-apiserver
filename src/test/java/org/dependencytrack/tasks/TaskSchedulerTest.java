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
import alpine.event.framework.EventService;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.VulnerabilityScanCleanupEvent;
import org.dependencytrack.model.VulnerabilityScan;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class TaskSchedulerTest extends PersistenceCapableTest {

    TaskScheduler taskScheduler;
    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @BeforeClass
    public static void setUpClass() {
        Config.enableUnitTests();
        EventService.getInstance().subscribe(VulnerabilityScanCleanupEvent.class, VulnerabilityScanCleanupTask.class);
    }

    @AfterClass
    public static void tearDownClass() {
        EventService.getInstance().unsubscribe(VulnerabilityScanCleanupTask.class);
    }

    @Before
    public void before() throws Exception {
        environmentVariables.set("TASK_CRON_VULNSCANCLEANUP", "* * * * * *");
        environmentVariables.set("TASK_SCHEDULER_INITIAL_DELAY", "5");
        environmentVariables.set("TASK_SCHEDULER_POLLING_INTERVAL", "1000");
        super.before();
    }

    @After
    public void after() {
        environmentVariables.clear("TASK_CRON_VULNSCANCLEANUP",
                "TASK_SCHEDULER_INITIAL_DELAY",
                "TASK_SCHEDULER_POLLING_INTERVAL");
        taskScheduler.shutdown();
        super.after();
    }

    @Test
    public void test() throws Exception {

        taskScheduler = TaskScheduler.getInstance();

        qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, UUID.randomUUID(), "token-123", 5);
        final var scanB = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, UUID.randomUUID(), "token-xyz", 1);
        qm.runInTransaction(() -> scanB.setUpdatedAt(Date.from(Instant.now().minus(25, ChronoUnit.HOURS))));
        final var scanC = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, UUID.randomUUID(), "token-1y3", 3);
        qm.runInTransaction(() -> scanC.setUpdatedAt(Date.from(Instant.now().minus(13, ChronoUnit.HOURS))));
        //Sleeping for 500ms after initial delay so event would be sent
        Thread.sleep(1000);

        assertThat(qm.getVulnerabilityScan("token-123")).isNotNull();
        assertThat(qm.getVulnerabilityScan("token-xyz")).isNull();
        assertThat(qm.getVulnerabilityScan("token-1y3")).isNotNull();
    }
}
