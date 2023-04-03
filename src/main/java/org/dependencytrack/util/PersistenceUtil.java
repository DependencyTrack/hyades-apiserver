package org.dependencytrack.util;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.postgresql.util.PSQLState;

import java.sql.SQLException;

public final class PersistenceUtil {

    private PersistenceUtil() {
    }

    public static boolean isUniqueConstraintViolation(final Throwable throwable) {
        // TODO: DataNucleus doesn't map constraint violation exceptions very well,
        // so we have to depend on the exception of the underlying JDBC driver to
        // tell us what happened. We currently only handle PostgreSQL, but we'll have
        // to do the same for at least H2 and MSSQL.
        return ExceptionUtils.getRootCause(throwable) instanceof final SQLException se
                && PSQLState.UNIQUE_VIOLATION.getState().equals(se.getSQLState());
    }

}
