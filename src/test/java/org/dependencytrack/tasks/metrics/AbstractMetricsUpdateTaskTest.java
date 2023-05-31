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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.metrics;

import alpine.server.persistence.PersistenceManagerFactory;
import alpine.server.util.DbUtil;
import org.apache.commons.io.IOUtils;
import org.datanucleus.PropertyNames;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.persistence.QueryManager;
import org.junit.After;
import org.junit.Before;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import javax.jdo.datastore.JDOConnection;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

abstract class AbstractMetricsUpdateTaskTest {

    protected final String postgresImageTag;
    protected PostgreSQLContainer<?> postgresContainer;
    protected QueryManager qm;

    protected AbstractMetricsUpdateTaskTest(final String postgresImageTag) {
        this.postgresImageTag = postgresImageTag;
    }

    @Before
    public void setUp() throws Exception {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse(postgresImageTag))
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withDatabaseName("dtrack");
        postgresContainer.start();

        final var dnProps = new Properties();
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_DATABASE, "true");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_TABLES, "true");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_COLUMNS, "true");
        dnProps.put(PropertyNames.PROPERTY_SCHEMA_AUTOCREATE_CONSTRAINTS, "true");
        dnProps.put("datanucleus.schema.generatedatabase.mode", "create");
        dnProps.put("datanucleus.query.jdoql.allowall", "true");
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_URL, postgresContainer.getJdbcUrl());
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_DRIVER_NAME, postgresContainer.getDriverClassName());
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_USER_NAME, postgresContainer.getUsername());
        dnProps.put(PropertyNames.PROPERTY_CONNECTION_PASSWORD, postgresContainer.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

        qm = new QueryManager();

        final String storedProcs = IOUtils.resourceToString("/storedprocs-postgres.sql", StandardCharsets.UTF_8);
        final String shedlockSql = IOUtils.resourceToString("/shedlock.sql", StandardCharsets.UTF_8);
        final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
        final Connection connection = (Connection) jdoConnection.getNativeConnection();
        DbUtil.executeUpdate(connection, storedProcs);
        DbUtil.executeUpdate(connection, shedlockSql);
        jdoConnection.close();
    }

    @After
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    protected PolicyViolation createPolicyViolation(final Component component, final Policy.ViolationState violationState, final PolicyViolation.Type type) {
        final var policy = qm.createPolicy(UUID.randomUUID().toString(), Policy.Operator.ALL, violationState);
        final var policyCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "");
        final var policyViolation = new PolicyViolation();

        policyViolation.setComponent(component);
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setTimestamp(new Date());
        policyViolation.setType(type);
        return qm.addPolicyViolationIfNotExist(policyViolation);
    }

}
