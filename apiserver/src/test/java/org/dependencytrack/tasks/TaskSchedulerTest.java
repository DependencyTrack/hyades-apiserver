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
import org.dependencytrack.PersistenceCapableTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class TaskSchedulerTest extends PersistenceCapableTest {

    private TaskScheduler scheduler;

    @BeforeEach
    void beforeEach() {
        scheduler = new TaskScheduler(Duration.ZERO, Duration.ofMillis(10));
        scheduler.start();
    }

    @AfterEach
    void afterEach() {
        if (scheduler != null) {
            scheduler.close();
        }
    }

    @Test
    void shouldExecuteTaskOnSchedule() throws Exception {
        final var executed = new AtomicBoolean(false);

        scheduler.schedule("foo", Schedule.create("* * * * * *"), () -> executed.set(true));

        await("Task execution")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(executed).isTrue());
    }

    @Test
    void closeShouldNoopWhenAlreadyStopped() {
        assertThatNoException().isThrownBy(scheduler::close);
        assertThatNoException().isThrownBy(scheduler::close);
    }

    @Test
    void shouldFireImmediatelyWhenExecutionWasMissed() throws Exception {
        seedLastExecutedAt("missed-task", Instant.now().minus(Duration.ofMinutes(5)));

        final var executed = new AtomicBoolean(false);
        scheduler.schedule("missed-task", Schedule.create("0 * * * * *"), () -> executed.set(true));

        await("Missed trigger catch-up")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(executed).isTrue());
    }

    @Test
    void shouldNotFireImmediatelyWhenNotPreviouslyExecutedAndTriggerOnFirstRunIsFalse() throws Exception {
        final var executed = new AtomicBoolean(false);

        scheduler.schedule("new-task", Schedule.create("0 0 0 1 1 *"), () -> executed.set(true));

        await("Task should not execute")
                .during(Duration.ofMillis(500))
                .untilAsserted(() -> assertThat(executed).isFalse());
    }

    @Test
    void shouldFireImmediatelyWhenNotPreviouslyExecutedAndTriggerOnFirstRunIsTrue() throws Exception {
        final var executed = new AtomicBoolean(false);

        scheduler.schedule("first-run-task", Schedule.create("0 0 0 1 1 *"), () -> executed.set(true), true);

        await("First run trigger")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(executed).isTrue());
    }

    @Test
    void shouldRecordLastExecutedAtOnExecution() throws Exception {
        scheduler.schedule("foo", Schedule.create("* * * * * *"), () -> {
        });

        await("Last execution recorded")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(getLastExecutedAt("foo")).isNotNull());
    }

    @Test
    void shouldNotFireImmediatelyWhenLastExecutionIsRecentAndNoExecutionMissed() throws Exception {
        seedLastExecutedAt("recent-task", Instant.now());

        final var executed = new AtomicBoolean(false);
        scheduler.schedule("recent-task", Schedule.create("0 0 0 1 1 *"), () -> executed.set(true));

        await("Task should not execute")
                .during(Duration.ofMillis(500))
                .untilAsserted(() -> assertThat(executed).isFalse());
    }

    private static void seedLastExecutedAt(String taskId, Instant lastExecutedAt) {
        useJdbiHandle(handle -> handle.createUpdate("""
                        INSERT INTO "SCHEDULED_TASK_EXECUTION" ("TASK_ID", "LAST_EXECUTED_AT", "LOCK_VERSION")
                        VALUES (:taskId, :lastExecutedAt, 0)
                        ON CONFLICT ("TASK_ID") DO UPDATE
                        SET "LAST_EXECUTED_AT" = EXCLUDED."LAST_EXECUTED_AT"
                          , "LOCK_VERSION" = "SCHEDULED_TASK_EXECUTION"."LOCK_VERSION" + 1
                        """)
                .bind("taskId", taskId)
                .bind("lastExecutedAt", lastExecutedAt)
                .execute());
    }

    private static Instant getLastExecutedAt(String taskId) {
        return withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "LAST_EXECUTED_AT"
                          FROM "SCHEDULED_TASK_EXECUTION"
                         WHERE "TASK_ID" = :taskId
                        """)
                .bind("taskId", taskId)
                .mapTo(Instant.class)
                .findOne()
                .orElse(null));
    }

}
