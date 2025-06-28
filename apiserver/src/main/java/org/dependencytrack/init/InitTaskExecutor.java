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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextListener;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.ServiceLoader;

import static java.util.Comparator.comparingInt;
import static java.util.Objects.requireNonNull;

/**
 * @since 5.6.0
 */
public final class InitTaskExecutor implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(InitTaskExecutor.class);
    private static final String ADVISORY_LOCK_NAME = "dependency-track-init-tasks";

    private final Config config;
    private final DataSource dataSource;
    private final List<InitTask> tasks;

    public InitTaskExecutor(final Config config, final DataSource dataSource) {
        this(config, dataSource, loadInitTasks());
    }

    InitTaskExecutor(final Config config, final DataSource dataSource, final List<InitTask> tasks) {
        this.config = requireNonNull(config, "config must not be null");
        this.dataSource = requireNonNull(dataSource, "dataSource must not be null");
        this.tasks = requireNonNull(tasks, "tasks must not be null");
    }

    public void execute() {
        final List<InitTask> orderedTasks = this.tasks.stream()
                // TODO: Allow individual tasks to be disabled.
                .sorted(comparingInt(InitTask::priority)
                        .thenComparing(InitTask::name))
                .toList();

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement lockStatement = connection.prepareStatement("""
                     select pg_advisory_lock(?)
                     """)) {
            LOGGER.debug("Trying to acquiring lock");
            lockStatement.setLong(1, ADVISORY_LOCK_NAME.hashCode());
            lockStatement.execute();
            LOGGER.debug("Lock acquired");

            final var taskContext = new InitTaskContext(config, dataSource);

            for (final InitTask task : orderedTasks) {
                LOGGER.info("Executing init task: {}", task.name());
                try {
                    task.execute(taskContext);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to execute init task " + task.name(), e);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to acquire lock", e);
        }
    }

    private static List<InitTask> loadInitTasks() {

        return ServiceLoader.load(InitTask.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
    }

}
