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
package org.dependencytrack.init;

import alpine.Config;
import org.dependencytrack.PersistenceCapableTest;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;
import static org.mockito.Mockito.mock;

public class InitTaskExecutorTest extends PersistenceCapableTest {

    private Config configMock;
    private PGSimpleDataSource dataSource;

    @Before
    public void before() throws Exception {
        super.before();

        configMock = mock(Config.class);

        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
    }

    @Test
    public void shouldExecuteTasksInPriorityOrder() {
        final var executedTaskNames = new ArrayList<String>(3);

        final var executor = new InitTaskExecutor(configMock, dataSource, List.of(
                new TestInitTask(5, "a", () -> executedTaskNames.add("a")),
                new TestInitTask(1, "b", () -> executedTaskNames.add("b")),
                new TestInitTask(3, "c", () -> executedTaskNames.add("c"))));
        executor.execute();

        assertThat(executedTaskNames).containsExactly("b", "c", "a");
    }

    @Test
    public void shouldThrowWhenTaskExecutionFails() {
        final var executor = new InitTaskExecutor(configMock, dataSource, List.of(
                new TestInitTask(1, "test", () -> {
                    throw new IllegalStateException("boom");
                })));

        assertThatException()
                .isThrownBy(executor::execute)
                .withMessage("Failed to execute init task test")
                .withCauseInstanceOf(IllegalStateException.class);
    }

    private static final class TestInitTask implements InitTask {

        private final int priority;
        private final String name;
        private final Runnable runnable;

        private TestInitTask(int priority, String name, Runnable runnable) {
            this.priority = priority;
            this.name = name;
            this.runnable = runnable;
        }

        @Override
        public int priority() {
            return priority;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public void execute(final InitTaskContext ctx) {
            if (runnable != null) {
                runnable.run();
            }
        }

    }

}