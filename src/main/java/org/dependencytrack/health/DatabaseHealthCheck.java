package org.dependencytrack.health;

import alpine.server.persistence.PersistenceManagerFactory;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;

import javax.jdo.PersistenceManager;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * A {@link HealthCheck} for database connections.
 */
class DatabaseHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        final var responseBuilder = HealthCheckResponse.named("database");

        try (final PersistenceManager pm = PersistenceManagerFactory.createPersistenceManager()) {
            if (pm.getPersistenceManagerFactory() instanceof final JDOPersistenceManagerFactory pmf
                    && pmf.getNucleusContext().getStoreManager() instanceof final RDBMSStoreManager storeManager
                    && storeManager.getConnectionManager() instanceof final ConnectionManagerImpl connectionManager) {
                final HealthCheckResponse.Status primaryStatus = checkConnectionFactory(FieldUtils.readField(connectionManager, "primaryConnectionFactory", true));
                final HealthCheckResponse.Status secondaryStatus = checkConnectionFactory(FieldUtils.readField(connectionManager, "secondaryConnectionFactory", true));

                if (primaryStatus == HealthCheckResponse.Status.UP && secondaryStatus == HealthCheckResponse.Status.UP) {
                    responseBuilder.up();
                } else {
                    responseBuilder.down();
                }

                responseBuilder
                        .withData("primaryConnectionFactory", primaryStatus.name())
                        .withData("secondaryConnectionFactory", secondaryStatus.name());
            }
        } catch (Exception e) {
            responseBuilder.down()
                    .withData("exception_message", e.getMessage());
        }

        return responseBuilder.build();
    }

    private HealthCheckResponse.Status checkConnectionFactory(final Object connectionFactory) throws Exception {
        if (connectionFactory instanceof final ConnectionFactoryImpl connectionFactoryImpl) {
            final Object dataSource = FieldUtils.readField(connectionFactoryImpl, "dataSource", true);
            if (dataSource instanceof final HikariDataSource hikariDataSource) {
                try (final Connection connection = hikariDataSource.getConnection()) {
                    return HealthCheckResponse.Status.UP;
                } catch (SQLException e) {
                    return HealthCheckResponse.Status.DOWN;
                }
            }
        }

        return HealthCheckResponse.Status.DOWN;
    }

}
