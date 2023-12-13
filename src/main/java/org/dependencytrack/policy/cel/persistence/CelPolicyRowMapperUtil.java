package org.dependencytrack.policy.cel.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.function.Consumer;

class CelPolicyRowMapperUtil {

    static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private CelPolicyRowMapperUtil() {
    }

    static <V> void maybeSet(final ResultSet rs, final String columnName, final ThrowingFunction<V> getter, final Consumer<V> setter) throws SQLException {
        if (!hasColumn(rs, columnName)) {
            return;
        }

        final V value = getter.apply(columnName);
        if (value != null) {
            setter.accept(value);
        }
    }

    interface ThrowingFunction<V> {
        V apply(final String key) throws SQLException;
    }

    static boolean hasColumn(final ResultSet rs, final String columnName) throws SQLException {
        try {
            return rs.findColumn(columnName) >= 0;
        } catch (SQLException e) {
            if (e instanceof final PSQLException pe) {
                if (PSQLState.UNDEFINED_COLUMN.getState().equals(pe.getSQLState())) {
                    return false;
                }
            }

            throw e;
        }
    }

}
