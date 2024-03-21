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
package org.dependencytrack.util;

import alpine.Config;
import net.javacrumbs.shedlock.core.DefaultLockingTaskExecutor;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import net.javacrumbs.shedlock.provider.jdbc.JdbcLockProvider;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.LockName;

import javax.jdo.PersistenceManager;
import javax.sql.DataSource;
import java.time.Duration;
import java.time.Instant;

import static org.dependencytrack.common.ConfigKey.INTEGRITY_META_INITIALIZER_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.INTEGRITY_META_INITIALIZER_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_COMPONENT_IDENTIFICATION_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_COMPONENT_IDENTIFICATION_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_LDAP_SYNC_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_LDAP_SYNC_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_METRICS_VULNERABILITY_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_METRICS_VULNERABILITY_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_MIRROR_EPSS_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_MIRROR_EPSS_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_PORTFOLIO_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_PORTFOLIO_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_PORTFOLIO_REPO_META_ANALYSIS_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_PORTFOLIO_REPO_META_ANALYSIS_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_PORTFOLIO_VULN_ANALYSIS_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_PORTFOLIO_VULN_ANALYSIS_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_VULNERABILITY_POLICY_BUNDLE_FETCH_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_VULNERABILITY_POLICY_BUNDLE_FETCH_LOCK_AT_MOST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_WORKFLOW_STEP_CLEANUP_LOCK_AT_LEAST_FOR;
import static org.dependencytrack.common.ConfigKey.TASK_WORKFLOW_STEP_CLEANUP_LOCK_AT_MOST_FOR;
import static org.dependencytrack.tasks.LockName.EPSS_MIRROR_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.INTEGRITY_META_INITIALIZER_LOCK;
import static org.dependencytrack.tasks.LockName.INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.LDAP_SYNC_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.PORTFOLIO_METRICS_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.PORTFOLIO_REPO_META_ANALYSIS_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.PORTFOLIO_VULN_ANALYSIS_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.VULNERABILITY_METRICS_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.VULNERABILITY_POLICY_BUNDLE_FETCH_TASK_LOCK;
import static org.dependencytrack.tasks.LockName.WORKFLOW_STEP_CLEANUP_TASK_LOCK;

public class LockProvider {

    private static JdbcLockProvider instance;

    private static LockingTaskExecutor lockingTaskExecutor;

    public static void executeWithLock(LockName lockName, Runnable task) {
        LockConfiguration lockConfiguration = getLockConfigurationByLockName(lockName);
        LockingTaskExecutor executor = getLockingTaskExecutorInstance();
        executor.executeWithLock(task, lockConfiguration);
    }

    public static void executeWithLock(LockName lockName, LockingTaskExecutor.Task task) throws Throwable {
        LockConfiguration lockConfiguration = getLockConfigurationByLockName(lockName);
        LockingTaskExecutor executor = getLockingTaskExecutorInstance();
        executor.executeWithLock(task, lockConfiguration);
    }

    private static JdbcLockProvider getJdbcLockProviderInstance() {
       if(instance == null || Config.isUnitTestsEnabled()) {
           try (final QueryManager qm = new QueryManager()) {
               PersistenceManager pm = qm.getPersistenceManager();
               JDOPersistenceManagerFactory pmf = (JDOPersistenceManagerFactory) pm.getPersistenceManagerFactory();
               instance =  new JdbcLockProvider(getDataSource(pmf));
           } catch (IllegalAccessException e) {
               throw new RuntimeException("Failed to access data source", e);
           }
       }
       return instance;
    }

    private static LockingTaskExecutor getLockingTaskExecutorInstance() {
        JdbcLockProvider jdbcLockProvider = getJdbcLockProviderInstance();
        if(lockingTaskExecutor == null || Config.isUnitTestsEnabled()) {
            lockingTaskExecutor = new DefaultLockingTaskExecutor(jdbcLockProvider);
        }
        return lockingTaskExecutor;
    }

    private static DataSource getDataSource(final JDOPersistenceManagerFactory pmf) throws IllegalAccessException {
        // DataNucleus doesn't provide access to the underlying DataSource
        // after the PMF has been created. We use reflection to still get access
        if (pmf.getNucleusContext().getStoreManager() instanceof final RDBMSStoreManager storeManager
                && storeManager.getConnectionManager() instanceof final ConnectionManagerImpl connectionManager) {
            return getDataSourceUsingReflection(FieldUtils.readField(connectionManager, "primaryConnectionFactory", true));
        }
        return null;
    }

    private static DataSource getDataSourceUsingReflection(final Object connectionFactory) throws IllegalAccessException {
        if (connectionFactory instanceof final ConnectionFactoryImpl connectionFactoryImpl) {
            final Object dataSource = FieldUtils.readField(connectionFactoryImpl, "dataSource", true);
            return (DataSource) dataSource;
        }
        return null;
    }

    public static LockConfiguration getLockConfigurationByLockName(LockName lockName) {
        return switch(lockName) {
            case PORTFOLIO_METRICS_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    PORTFOLIO_METRICS_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_PORTFOLIO_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_PORTFOLIO_LOCK_AT_LEAST_FOR)));
            case LDAP_SYNC_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    LDAP_SYNC_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_LDAP_SYNC_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_LDAP_SYNC_LOCK_AT_LEAST_FOR)));
            case EPSS_MIRROR_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    EPSS_MIRROR_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_MIRROR_EPSS_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_MIRROR_EPSS_LOCK_AT_LEAST_FOR)));
            case VULNERABILITY_METRICS_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    VULNERABILITY_METRICS_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_METRICS_VULNERABILITY_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_METRICS_VULNERABILITY_LOCK_AT_LEAST_FOR)));
            case INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_COMPONENT_IDENTIFICATION_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_COMPONENT_IDENTIFICATION_LOCK_AT_LEAST_FOR)));
            case WORKFLOW_STEP_CLEANUP_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    WORKFLOW_STEP_CLEANUP_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_WORKFLOW_STEP_CLEANUP_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_WORKFLOW_STEP_CLEANUP_LOCK_AT_LEAST_FOR)));
            case PORTFOLIO_REPO_META_ANALYSIS_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    PORTFOLIO_REPO_META_ANALYSIS_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_PORTFOLIO_REPO_META_ANALYSIS_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_PORTFOLIO_REPO_META_ANALYSIS_LOCK_AT_LEAST_FOR)));
            case PORTFOLIO_VULN_ANALYSIS_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    PORTFOLIO_VULN_ANALYSIS_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_PORTFOLIO_VULN_ANALYSIS_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_PORTFOLIO_VULN_ANALYSIS_LOCK_AT_LEAST_FOR)));
            case INTEGRITY_META_INITIALIZER_LOCK -> new LockConfiguration(Instant.now(),
                    INTEGRITY_META_INITIALIZER_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(INTEGRITY_META_INITIALIZER_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(INTEGRITY_META_INITIALIZER_LOCK_AT_LEAST_FOR)));
            case VULNERABILITY_POLICY_BUNDLE_FETCH_TASK_LOCK -> new LockConfiguration(Instant.now(),
                    VULNERABILITY_POLICY_BUNDLE_FETCH_TASK_LOCK.name(),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_VULNERABILITY_POLICY_BUNDLE_FETCH_LOCK_AT_MOST_FOR)),
                    Duration.ofMillis(Config.getInstance().getPropertyAsInt(TASK_VULNERABILITY_POLICY_BUNDLE_FETCH_LOCK_AT_LEAST_FOR)));
        };

    }

    public static boolean isLockToBeExtended(long cumulativeDurationInMillis, LockName lockName) {
        LockConfiguration lockConfiguration = LockProvider.getLockConfigurationByLockName(lockName);
        return cumulativeDurationInMillis >=  (lockConfiguration.getLockAtMostFor().minus(lockConfiguration.getLockAtLeastFor())).toMillis() ? true : false;
    }
}
