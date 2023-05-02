package org.dependencytrack.persistence;

import alpine.common.logging.Logger;
import alpine.server.util.DbUtil;
import org.apache.commons.io.IOUtils;

import javax.jdo.datastore.JDOConnection;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * A {@link ServletContextListener} that ensures that stored procedures are available.
 *
 * @since 5.0.0
 */
public class StoredProcedureInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(StoredProcedureInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        try (final var qm = new QueryManager()) {
            final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
            try {
                final Connection connection = (Connection) jdoConnection.getNativeConnection();

                DbUtil.initPlatformName(connection);
                if (!DbUtil.isPostgreSQL()) {
                    LOGGER.warn("Stored procedures are only supported for PostgreSQL");
                    return;
                }

                final String storedProcs = IOUtils.resourceToString("/storedprocs-postgres.sql", StandardCharsets.UTF_8);
                DbUtil.executeUpdate(connection, storedProcs);
            } catch (SQLException | IOException e) {
                throw new RuntimeException("Initializing stored procedures failed", e);
            } finally {
                jdoConnection.close();
            }
        }
    }
}
