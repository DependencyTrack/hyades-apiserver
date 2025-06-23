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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Repository;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class DefaultObjectGeneratorTest extends PersistenceCapableTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void testContextInitialized() throws Exception {
        testLoadDefaultPermissions();
        testLoadDefaultPersonas();
        testLoadDefaultLicenses();
        testLoadDefaultRepositories();
        testLoadDefaultConfigProperties();
        testLoadDefaultNotificationPublishers();
    }

    @Test
    public void testWithInitTasksDisabled() {
        environmentVariables.set(ConfigKey.INIT_TASKS_ENABLED.name(), "false");

        new DefaultObjectGenerator().contextInitialized(null);

        assertThat(qm.getPermissions()).isEmpty();
        assertThat(qm.getManagedUsers()).isEmpty();
        assertThat(qm.getLicenses().getList(License.class)).isEmpty();
        assertThat(qm.getRepositories().getList(Repository.class)).isEmpty();
        assertThat(qm.getConfigProperties()).isEmpty();
        assertThat(qm.getAllNotificationPublishers()).isEmpty();
    }

    @Test
    public void testWithDefaultObjectsAlreadyPopulated() {
        new DefaultObjectGenerator().contextInitialized(null);

        List<License> licenses = qm.getLicenses().getList(License.class);
        assertThat(licenses).isNotEmpty();

        qm.delete(licenses);

        new DefaultObjectGenerator().contextInitialized(null);

        // Default objects must not have been populated again, since their
        // version is already current for this application build.
        licenses = qm.getLicenses().getList(License.class);
        assertThat(licenses).isEmpty();
    }

    @Test
    public void testLoadDefaultLicenses() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.loadDefaultLicenses();
        Assert.assertEquals(738, qm.getAllLicensesConcise().size());
    }

    @Test
    public void testLoadDefaultLicensesUpdatesExistingLicenses() throws Exception {
        final var license = new License();
        license.setLicenseId("LGPL-2.1+");
        license.setName("name");
        license.setComment("comment");
        license.setHeader("header");
        license.setSeeAlso("seeAlso");
        license.setTemplate("template");
        license.setText("text");
        qm.persist(license);

        final var generator = new DefaultObjectGenerator();
        generator.loadDefaultLicenses();

        qm.getPersistenceManager().refresh(license);
        assertThat(license.getLicenseId()).isEqualTo("LGPL-2.1+");
        assertThat(license.getName()).isEqualTo("GNU Lesser General Public License v2.1 or later");
        assertThat(license.getComment()).isNotEqualTo("comment");
        assertThat(license.getHeader()).isNotEqualTo("header");
        assertThat(license.getSeeAlso()).isNotEqualTo(new String[]{"seeAlso"});
        assertThat(license.getTemplate()).isNotEqualTo("template");
        assertThat(license.getText()).isNotEqualTo("text");
    }

    @Test
    public void testLoadDefaultPermissions() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.loadDefaultPermissions();
        Assert.assertEquals(Permissions.values().length, qm.getPermissions().size());
    }

    @Test
    public void testLoadDefaultPersonas() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.loadDefaultPersonas();
        Assert.assertEquals(4, qm.getTeams(null).getTotal());
    }

    @Test
    public void testLoadDefaultRepositories() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.loadDefaultRepositories();
        Assert.assertEquals(17, qm.getAllRepositories().size());
    }

    @Test
    public void testLoadDefaultConfigProperties() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.loadDefaultConfigProperties();
        Assert.assertEquals(ConfigPropertyConstants.values().length, qm.getConfigProperties().size());
    }

    @Test
    public void testLoadDefaultNotificationPublishers() throws Exception {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.loadDefaultNotificationPublishers();
        Assert.assertEquals(DefaultNotificationPublishers.values().length, qm.getAllNotificationPublishers().size());
    }

    @Test
    public void testMetricsPartitionsForTodayAndTomorrow() {
        DefaultObjectGenerator generator = new DefaultObjectGenerator();
        generator.ensureMetricsPartitions();
        var today = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
        var tomorrow = LocalDate.now().plusDays(1).format(DateTimeFormatter.BASIC_ISO_DATE);
        withJdbiHandle(handle -> {
            var metricsHandle = handle.attach(MetricsDao.class);
            assertThat(Collections.frequency(metricsHandle.getPortfolioMetricsPartitions(), "\"PORTFOLIOMETRICS_%s\"".formatted(today))).isEqualTo(1);
            assertThat(Collections.frequency(metricsHandle.getPortfolioMetricsPartitions(), "\"PORTFOLIOMETRICS_%s\"".formatted(tomorrow))).isEqualTo(1);
            assertThat(Collections.frequency(metricsHandle.getProjectMetricsPartitions(), "\"PROJECTMETRICS_%s\"".formatted(today))).isEqualTo(1);
            assertThat(Collections.frequency(metricsHandle.getProjectMetricsPartitions(), "\"PROJECTMETRICS_%s\"".formatted(tomorrow))).isEqualTo(1);
            assertThat(Collections.frequency(metricsHandle.getDependencyMetricsPartitions(), "\"DEPENDENCYMETRICS_%s\"".formatted(today))).isEqualTo(1);
            assertThat(Collections.frequency(metricsHandle.getDependencyMetricsPartitions(), "\"DEPENDENCYMETRICS_%s\"".formatted(tomorrow))).isEqualTo(1);
            return null;
        });
    }
}
