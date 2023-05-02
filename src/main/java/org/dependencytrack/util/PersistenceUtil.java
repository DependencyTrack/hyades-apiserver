package org.dependencytrack.util;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.datanucleus.api.jdo.JDOQuery;
import org.datanucleus.store.rdbms.query.StoredProcedureQuery;
import org.dependencytrack.persistence.QueryManager;
import org.postgresql.util.PSQLState;

import javax.jdo.Query;
import java.sql.SQLException;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

public final class PersistenceUtil {

    private PersistenceUtil() {
    }

    public static <T, V> boolean applyIfChanged(final T existingObject, final T newObject,
                                                final Function<T, V> getter, final Consumer<V> setter) {
        final V existingValue = getter.apply(existingObject);
        final V newValue = getter.apply(newObject);

        if (!Objects.equals(existingValue, newValue)) {
            setter.accept(newValue);
            return true;
        }

        return false;
    }

    public static <T, V> boolean applyIfNonNullAndChanged(final T existingObject, final T newObject,
                                                          final Function<T, V> getter, final Consumer<V> setter) {
        final V existingValue = getter.apply(existingObject);
        final V newValue = getter.apply(newObject);

        if (newValue != null && !Objects.equals(existingValue, newValue)) {
            setter.accept(newValue);
            return true;
        }

        return false;
    }

    public static boolean isUniqueConstraintViolation(final Throwable throwable) {
        // TODO: DataNucleus doesn't map constraint violation exceptions very well,
        // so we have to depend on the exception of the underlying JDBC driver to
        // tell us what happened. We currently only handle PostgreSQL, but we'll have
        // to do the same for at least H2 and MSSQL.
        return ExceptionUtils.getRootCause(throwable) instanceof final SQLException se
                && PSQLState.UNIQUE_VIOLATION.getState().equals(se.getSQLState());
    }

    /**
     * Execute a given stored procedure.
     *
     * @param name Name of the stored procedure to execute
     * @since 5.0.0
     */
    public static void executeStoredProcedure(final String name) {
        executeStoredProcedure(name, query -> {
        });
    }

    /**
     * Execute a given stored procedure and customize the execution.
     *
     * @param name          Name of the stored procedure to execute
     * @param queryConsumer {@link Consumer} for customizing the {@link StoredProcedureQuery}
     * @since 5.0.0
     */
    public static void executeStoredProcedure(final String name, final Consumer<StoredProcedureQuery> queryConsumer) {
        try (final var qm = new QueryManager()) {
            final Query<?> query = qm.getPersistenceManager().newQuery("STOREDPROC", "\"%s\"".formatted(name));
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
