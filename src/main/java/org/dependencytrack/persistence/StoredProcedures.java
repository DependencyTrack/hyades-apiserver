package org.dependencytrack.persistence;

import org.datanucleus.api.jdo.JDOQuery;
import org.datanucleus.store.rdbms.query.StoredProcedureQuery;

import javax.jdo.Query;
import java.util.function.Consumer;

/**
 * Utility class to work with database stored procedures.
 *
 * @since 5.0.0
 */
public final class StoredProcedures {

    public enum Procedure {
        UPDATE_COMPONENT_METRICS,
        UPDATE_PROJECT_METRICS,
        UPDATE_PORTFOLIO_METRICS;

        private String quotedName() {
            // We use quoted identifiers by convention.
            return "\"%s\"".formatted(name());
        }
    }

    private StoredProcedures() {
    }

    /**
     * Execute a given stored procedure.
     *
     * @param procedure The {@link Procedure} to execute
     * @since 5.0.0
     */
    public static void execute(final Procedure procedure) {
        execute(procedure, query -> {
        });
    }

    /**
     * Execute a given stored procedure and customize the execution.
     *
     * @param procedure     The {@link Procedure} to execute
     * @param queryConsumer {@link Consumer} for customizing the {@link StoredProcedureQuery}
     * @since 5.0.0
     */
    public static void execute(final Procedure procedure, final Consumer<StoredProcedureQuery> queryConsumer) {
        try (final var qm = new QueryManager()) {
            final Query<?> query = qm.getPersistenceManager().newQuery("STOREDPROC", procedure.quotedName());
            try {
                final var spQuery = (StoredProcedureQuery) ((JDOQuery<?>) query).getInternalQuery();
                queryConsumer.accept(spQuery);
                spQuery.execute();
            } finally {
                query.closeAll();
            }
        }
    }

}
