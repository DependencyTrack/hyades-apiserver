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
package org.dependencytrack.tasks.metrics;

import net.jcip.annotations.NotThreadSafe;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.MetricsPartitionCreateEvent;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.junit.Test;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@NotThreadSafe
public class MetricsPartitionCreateTaskTest extends PersistenceCapableTest {

    @Test
    public void testCreateMetricsPartitions() {

        new MetricsPartitionCreateTask().inform(new MetricsPartitionCreateEvent());
        withJdbiHandle(handle -> {
            var metricsHandle = handle.attach(MetricsDao.class);
            var today = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
            var metricsPartition = metricsHandle.getPortfolioMetricsPartitions();
            assertThat(metricsPartition.size()).isEqualTo(1);
            assertThat(metricsPartition.get(0)).isEqualTo("\"PORTFOLIOMETRICS_%s\"".formatted(today));

            metricsPartition = metricsHandle.getProjectMetricsPartitions();
            assertThat(metricsPartition.size()).isEqualTo(1);
            assertThat(metricsPartition.get(0)).isEqualTo("\"PROJECTMETRICS_%s\"".formatted(today));

            metricsPartition = metricsHandle.getDependencyMetricsPartitions();
            assertThat(metricsPartition.size()).isEqualTo(1);
            assertThat(metricsPartition.get(0)).isEqualTo("\"DEPENDENCYMETRICS_%s\"".formatted(today));
            return null;
        });
    }

    @Test
    public void testUpdateMetricsUnchanged() throws Exception {

        // Record initial metrics partition for today
        new MetricsPartitionCreateTask().inform(new MetricsPartitionCreateEvent());

        //sleep for the least duration lock held for, so lock could be released
        Thread.sleep(2000);

        // Run the task a second time, with partition for today already created
        final var beforeSecondRun = new Date();
        new MetricsPartitionCreateTask().inform(new MetricsPartitionCreateEvent());

        // Ensure that only 1 partition exists for today
        withJdbiHandle(handle -> {
            var metricsHandle = handle.attach(MetricsDao.class);
            assertThat(metricsHandle.getPortfolioMetricsPartitions().size()).isEqualTo(1);
            assertThat(metricsHandle.getProjectMetricsPartitions().size()).isEqualTo(1);
            assertThat(metricsHandle.getDependencyMetricsPartitions().size()).isEqualTo(1);
            return null;
        });
    }
}