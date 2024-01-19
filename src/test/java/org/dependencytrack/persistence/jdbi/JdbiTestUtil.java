package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.persistence.QueryManager;
import org.jdbi.v3.core.Jdbi;

public final class JdbiTestUtil {

    private JdbiTestUtil() {
    }

    /**
     * Create a {@link Jdbi} instance from a {@link QueryManager}, without any of
     * the plugins and extensions registered by {@link JdbiFactory}.
     *
     * @param qm The {@link QueryManager} to use
     * @return A new {@link Jdbi} instance
     */
    public static Jdbi createLocalVanillaJdbi(final QueryManager qm) {
        return Jdbi.create(new JdoConnectionFactory(qm.getPersistenceManager()));
    }

}
