package org.dependencytrack.persistence;

import org.apache.commons.io.IOUtils;

import javax.jdo.datastore.JDOConnection;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;

import static alpine.server.util.DbUtil.executeUpdate;

public class ShedlockInitializer implements ServletContextListener {

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        try (final var qm = new QueryManager()) {
            final JDOConnection jdoConnection = qm.getPersistenceManager().getDataStoreConnection();
            try {
                final Connection connection = (Connection) jdoConnection.getNativeConnection();
                final String shedlockSql = IOUtils.resourceToString("/shedlock.sql", StandardCharsets.UTF_8);
                executeUpdate(connection, shedlockSql);
            } catch (SQLException | IOException e) {
                throw new RuntimeException("Failed to create shedlock table", e);
            } finally {
                jdoConnection.close();
            }
        }
    }
}
