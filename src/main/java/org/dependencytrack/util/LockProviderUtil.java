package org.dependencytrack.util;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;

import javax.sql.DataSource;

public class LockProviderUtil {
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
