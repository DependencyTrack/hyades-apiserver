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

import com.asahaf.javacron.Schedule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class TaskSchedulerTest  {

    private TaskScheduler scheduler;

    @Before
    public void beforeEach() {
        scheduler = new TaskScheduler();
        scheduler.start();
    }

    @After
    public void afterEach() {
        if (scheduler != null) {
            scheduler.close();
        }
    }

    @Test
    public void shouldExecuteTaskOnSchedule() throws Exception {
        final var executed = new AtomicBoolean(false);

        scheduler.schedule("foo", Schedule.create("* * * * * *"), () -> executed.set(true));

        await("Task execution")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(executed).isTrue());
    }

}