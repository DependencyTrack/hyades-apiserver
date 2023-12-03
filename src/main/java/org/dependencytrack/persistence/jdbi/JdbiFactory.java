package org.dependencytrack.persistence.jdbi;

import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;
import org.dependencytrack.persistence.QueryManager;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.sql.DataSource;
import java.sql.Connection;
import java.util.concurrent.atomic.AtomicReference;

import static org.apache.commons.lang3.reflect.FieldUtils.readField;

public class JdbiFactory {

    private static final AtomicReference<GlobalInstanceHolder> GLOBAL_INSTANCE_HOLDER = new AtomicReference<>();

    /**
     * Get a global {@link Jdbi} instance, initializing it if it hasn't been initialized before.
     * <p>
     * The global instance will use {@link Connection}s from the primary {@link DataSource}
     * of the given {@link QueryManager}'s {@link PersistenceManagerFactory}.
     * <p>
     * Usage of the global instance should be preferred to make the best possible use of JDBI's
     * internal caching mechanisms. However, this instance can't participate in transactions
     * initiated by JDO (via {@link QueryManager} or {@link PersistenceManager}).
     * <p>
     * If {@link Jdbi} usage in an active JDO {@link javax.jdo.Transaction} is desired,
     * use {@link #localJdbi(QueryManager)} instead, which will use the same {@link Connection}
     * as the provided {@link QueryManager}.
     *
     * @param qm The {@link QueryManager} to determine the {@link DataSource} from
     * @return The global {@link Jdbi} instance
     */
    public static Jdbi jdbi(final QueryManager qm) {
        return jdbi(qm.getPersistenceManager());
    }

    private static Jdbi jdbi(final PersistenceManager pm) {
        return GLOBAL_INSTANCE_HOLDER
                .updateAndGet(previous -> {
                    if (previous == null || previous.pmf != pm.getPersistenceManagerFactory()) {
                        // The PMF reference does not usually change, unless it has been recreated,
                        // or multiple PMFs exist in the same application. The latter is not the case
                        // for Dependency-Track, and the former only happens during test execution,
                        // where each test (re-)creates the PMF.
                        final Jdbi jdbi = createFromPmf(pm.getPersistenceManagerFactory());
                        return new GlobalInstanceHolder(jdbi, pm.getPersistenceManagerFactory());
                    }

                    return previous;
                })
                .jdbi();
    }

    /**
     * Create a new local {@link Jdbi} instance.
     * <p>
     * The instance will use the same {@link Connection} used by the given {@link QueryManager},
     * allowing it to participate in {@link javax.jdo.Transaction}s initiated by {@code qm}.
     * <p>
     * Because using local {@link Jdbi} instances has a high performance impact (e.g. due to ineffective caching),
     * this method will throw if {@code qm} is not participating in an active {@link javax.jdo.Transaction}
     * already.
     * <p>
     * Just like {@link QueryManager} itself, {@link Jdbi} instances created by this method are <em>not</em>
     * thread safe!
     *
     * @param qm The {@link QueryManager} to use the underlying {@link Connection} of
     * @return A new {@link Jdbi} instance
     * @throws IllegalStateException When the given {@link QueryManager} is not participating
     *                               in an active {@link javax.jdo.Transaction}
     */
    public static Jdbi localJdbi(final QueryManager qm) {
        return localJdbi(qm.getPersistenceManager());
    }

    private static Jdbi localJdbi(final PersistenceManager pm) {
        if (!pm.currentTransaction().isActive()) {
            throw new IllegalStateException("""
                    Local JDBI instances must not be used outside of an active JDO transaction. \
                    Use the global instance instead if combining JDBI with JDO transactions is not needed.""");
        }

        return Jdbi.create(new JdoConnectionFactory(pm));
    }

    private record GlobalInstanceHolder(Jdbi jdbi, PersistenceManagerFactory pmf) {
    }

    private static Jdbi createFromPmf(final PersistenceManagerFactory pmf) {
        try {
            if (pmf instanceof final JDOPersistenceManagerFactory jdoPmf
                    && jdoPmf.getNucleusContext().getStoreManager() instanceof final RDBMSStoreManager storeManager
                    && storeManager.getConnectionManager() instanceof final ConnectionManagerImpl connectionManager
                    && readField(connectionManager, "primaryConnectionFactory", true) instanceof ConnectionFactoryImpl connectionFactory
                    && readField(connectionFactory, "dataSource", true) instanceof final DataSource dataSource) {
                return Jdbi
                        .create(dataSource)
                        .installPlugin(new SqlObjectPlugin());
            }
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Failed to access datasource of PMF via reflection", e);
        }

        throw new IllegalStateException("Failed to access primary datasource of PMF");
    }

}
