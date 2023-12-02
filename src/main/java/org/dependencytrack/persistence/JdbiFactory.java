package org.dependencytrack.persistence;

import net.jcip.annotations.NotThreadSafe;
import org.jdbi.v3.core.ConnectionFactory;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.postgres.PostgresPlugin;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;

public class JdbiFactory {

    /**
     * Create a new {@link Jdbi} instance, using a {@link QueryManager}'s underlying database connection.
     * <p>
     * Note that the {@link QueryManager} will not be able to make any database interactions while
     * the {@link Jdbi} instance has any open {@link org.jdbi.v3.core.Handle}s.
     *
     * @param qm The {@link QueryManager} to source database connections from
     * @return A new {@link Jdbi} instance.
     */
    public static Jdbi jdbi(final QueryManager qm) {
        return jdbi(qm.getPersistenceManager());
    }

    private static Jdbi jdbi(final PersistenceManager pm) {
        return Jdbi
                .create(new JdoConnectionFactory(pm))
                .installPlugin(new SqlObjectPlugin())
                .installPlugin(new PostgresPlugin());
    }

    @NotThreadSafe
    private static final class JdoConnectionFactory implements ConnectionFactory {

        private final PersistenceManager pm;
        private JDOConnection jdoConnection;

        JdoConnectionFactory(final PersistenceManager pm) {
            this.pm = pm;
        }

        @Override
        public Connection openConnection() {
            if (jdoConnection != null) {
                throw new IllegalStateException("A JDO connection is already open");
            }

            jdoConnection = pm.getDataStoreConnection();
            return (Connection) jdoConnection.getNativeConnection();
        }

        @Override
        public void closeConnection(final Connection conn) {
            jdoConnection.close();
            jdoConnection = null;
        }

    }

}
