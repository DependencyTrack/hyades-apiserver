package org.dependencytrack.util;

import alpine.Config;
import net.javacrumbs.shedlock.core.DefaultLockingTaskExecutor;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import net.javacrumbs.shedlock.provider.jdbc.JdbcLockProvider;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.sql.DataSource;

public class LockProvider {

    private static JdbcLockProvider INSTANCE;

    private static LockingTaskExecutor LOCKING_TASK_EXECUTOR;

    public static JdbcLockProvider getJdbcLockProviderInstance() {
       if(INSTANCE == null || Config.isUnitTestsEnabled()) {
           try (final QueryManager qm = new QueryManager();
               PersistenceManager pm = qm.getPersistenceManager()) {
               JDOPersistenceManagerFactory pmf = (JDOPersistenceManagerFactory) pm.getPersistenceManagerFactory();
               INSTANCE =  new JdbcLockProvider(getDataSource(pmf));
           } catch (IllegalAccessException e) {
               throw new RuntimeException("Failed to access data source", e);
           }
       }
       return INSTANCE;
    }

    public static LockingTaskExecutor getLockingTaskExecutorInstance(JdbcLockProvider jdbcLockProvider) {
        if(LOCKING_TASK_EXECUTOR == null || Config.isUnitTestsEnabled()) {
            LOCKING_TASK_EXECUTOR = new DefaultLockingTaskExecutor(jdbcLockProvider);
        }
        return LOCKING_TASK_EXECUTOR;
    }

    public static DataSource getDataSource(final JDOPersistenceManagerFactory pmf) throws IllegalAccessException {
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
}
