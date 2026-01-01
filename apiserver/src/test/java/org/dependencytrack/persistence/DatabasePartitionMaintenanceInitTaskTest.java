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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class DatabasePartitionMaintenanceInitTaskTest extends PersistenceCapableTest {

    @Test
    public void testMetricsPartitionsForTodayAndTomorrow() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        new DatabasePartitionMaintenanceInitTask().execute(new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        var today = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
        var tomorrow = LocalDate.now().plusDays(1).format(DateTimeFormatter.BASIC_ISO_DATE);

        useJdbiHandle(handle -> {
            var metricsDao = handle.attach(MetricsDao.class);
            assertThat(Collections.frequency(metricsDao.getProjectMetricsPartitions(), "\"PROJECTMETRICS_%s\"".formatted(today))).isEqualTo(1);
            assertThat(Collections.frequency(metricsDao.getProjectMetricsPartitions(), "\"PROJECTMETRICS_%s\"".formatted(tomorrow))).isEqualTo(1);
            assertThat(Collections.frequency(metricsDao.getDependencyMetricsPartitions(), "\"DEPENDENCYMETRICS_%s\"".formatted(today))).isEqualTo(1);
            assertThat(Collections.frequency(metricsDao.getDependencyMetricsPartitions(), "\"DEPENDENCYMETRICS_%s\"".formatted(tomorrow))).isEqualTo(1);
        });
    }

}