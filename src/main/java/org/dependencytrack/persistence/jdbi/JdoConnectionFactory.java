package org.dependencytrack.persistence.jdbi;

import net.jcip.annotations.NotThreadSafe;
import org.jdbi.v3.core.ConnectionFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;

@NotThreadSafe
class JdoConnectionFactory implements ConnectionFactory {

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
