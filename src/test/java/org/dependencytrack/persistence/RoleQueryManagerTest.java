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

import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectRole;
import org.dependencytrack.model.ProjectRole.LdapUserProjectRole;
import org.dependencytrack.model.ProjectRole.ManagedUserProjectRole;
import org.dependencytrack.model.ProjectRole.OidcUserProjectRole;
import org.dependencytrack.model.Role;
import org.jdbi.v3.core.Jdbi;

import alpine.Config;
import alpine.model.ManagedUser;
import alpine.model.Permission;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import com.github.tomakehurst.wiremock.junit.WireMockRule;

public class RoleQueryManagerTest extends PersistenceCapableTest {

    private PostgreSQLContainer<?> postgresContainer;
    private Jdbi jdbi;

    @Before
    public void setUp() {
        System.setProperty("javax.jdo.PersistenceManagerFactoryClass",
                "org.datanucleus.api.jdo.JDOPersistenceManagerFactory");

        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"));
        postgresContainer.start();

        jdbi = Jdbi.create(
                postgresContainer.getJdbcUrl(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());
    }

    @After
    public void tearDown() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    // @BeforeClass
    // public static void beforeClass() {
    // Config.enableUnitTests();
    // }

    // @AfterClass
    // public static void afterClass() {
    // KafkaProducerInitializer.tearDown();
    // }

    // @Rule
    // public WireMockRule wireMockRule = new WireMockRule();

    @Test
    public void testGetUserProjectPermissions() throws ParseException {
        final var configMock = mock(Config.class);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_URL))).thenReturn(postgresContainer.getJdbcUrl());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_DRIVER)))
                .thenReturn(postgresContainer.getDriverClassName());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_USERNAME)))
                .thenReturn(postgresContainer.getUsername());
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_PASSWORD)))
                .thenReturn(postgresContainer.getPassword());
        when(configMock.getPropertyAsBoolean(eq(ConfigKey.INIT_TASKS_ENABLED))).thenReturn(true);
        when(configMock.getPropertyAsBoolean(eq(ConfigKey.DATABASE_RUN_MIGRATIONS))).thenReturn(true);

        final var testProject = new Project();
        testProject.setId(1);
        testProject.setName("test-project");
        testProject.setVersion("1.0.0");
        qm.persist(testProject);

        final var readPermission = new Permission();
        readPermission.setId(1);
        readPermission.setName("read");
        readPermission.setDescription("permission to read");
        qm.persist(readPermission);

        final var writePermission = new Permission();
        writePermission.setId(2);
        writePermission.setName("write");
        writePermission.setDescription("permission to write");
        qm.persist(writePermission);

        List<Permission> expectedPermissionsList = Arrays.asList(
                readPermission,
                writePermission);

        Set<Permission> expectedPermissions = new HashSet<>(expectedPermissionsList);

        final var testUser = new ManagedUser();
        testUser.setFullname("test user created for testing");
        testUser.setId(1);
        testUser.setUsername("test-user");
        DateFormat dateFormatter = new SimpleDateFormat("yyyyMMdd");
        testUser.setLastPasswordChange(dateFormatter.parse("20250324"));
        testUser.setPassword("password");
        qm.persist(testUser);

        final var maintainerRole = new Role();
        maintainerRole.setId(1);
        maintainerRole.setName("maintainer");
        maintainerRole.setPermissions(expectedPermissions);
        qm.persist(maintainerRole);

        // final var ldapUserProjectRole = new LdapUserProjectRole();
        // ldapUserProjectRole.setProject(testProject);

        final var managedUserProjectRole = new ManagedUserProjectRole();
        // managedUserProjectRole.setId(1);
        managedUserProjectRole.setProject(testProject);
        managedUserProjectRole.setManagedUsers(Arrays.asList(testUser));
        managedUserProjectRole.setRole(maintainerRole);
        // qm.persist(managedUserProjectRole);

        // final var oidcUserProjectRole = new OidcUserProjectRole();

        List<Permission> actualPermissions = qm.getUserProjectPermissions("test-user", "test-project");

        Assert.assertEquals(actualPermissions, expectedPermissionsList);
    }

}
