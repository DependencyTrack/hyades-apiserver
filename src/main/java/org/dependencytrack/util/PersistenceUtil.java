package org.dependencytrack.util;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.postgresql.util.PSQLState;

import javax.jdo.JDOHelper;
import javax.jdo.ObjectState;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

import static java.util.Collections.unmodifiableMap;
import static javax.jdo.ObjectState.HOLLOW_PERSISTENT_NONTRANSACTIONAL;
import static javax.jdo.ObjectState.PERSISTENT_CLEAN;
import static javax.jdo.ObjectState.PERSISTENT_DIRTY;
import static javax.jdo.ObjectState.PERSISTENT_NEW;
import static javax.jdo.ObjectState.PERSISTENT_NONTRANSACTIONAL_DIRTY;

public final class PersistenceUtil {

    private PersistenceUtil() {
    }

    public record Diff(Object before, Object after) {
    }

    public static final class Differ<T> {

        private final T existingObject;
        private final T newObject;
        private final Map<String, Diff> diffs;

        public Differ(final T existingObject, final T newObject) {
            this.existingObject = existingObject;
            this.newObject = newObject;
            this.diffs = new HashMap<>();
        }

        public <V> boolean applyIfChanged(final String fieldName, final Function<T, V> getter, final Consumer<V> setter) {
            final V existingValue = getter.apply(existingObject);
            final V newValue = getter.apply(newObject);

            if (!Objects.equals(existingValue, newValue)) {
                diffs.put(fieldName, new Diff(existingValue, newValue));
                setter.accept(newValue);
                return true;
            }

            return false;
        }

        public <V> boolean applyIfNonNullAndChanged(final String fieldName, final Function<T, V> getter, final Consumer<V> setter) {
            final V existingValue = getter.apply(existingObject);
            final V newValue = getter.apply(newObject);

            if (newValue != null && !Objects.equals(existingValue, newValue)) {
                diffs.put(fieldName, new Diff(existingValue, newValue));
                setter.accept(newValue);
                return true;
            }

            return false;
        }

        public Map<String, Diff> getDiffs() {
            return unmodifiableMap(diffs);
        }

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

    public static boolean isUniqueConstraintViolation(final Throwable throwable) {
        // TODO: DataNucleus doesn't map constraint violation exceptions very well,
        // so we have to depend on the exception of the underlying JDBC driver to
        // tell us what happened. We currently only handle PostgreSQL, but we'll have
        // to do the same for at least H2 and MSSQL.
        return ExceptionUtils.getRootCause(throwable) instanceof final SQLException se
                && PSQLState.UNIQUE_VIOLATION.getState().equals(se.getSQLState());
    }

    /**
     * Utility method to ensure that a given object is in a persistent state.
     * <p>
     * Useful when an object is supposed to be used as JDOQL query parameter,
     * or changes made on it are intended to be flushed to the database.
     * <p>
     * Performing these operations on a non-persistent object will have to effect.
     * It is preferable to catch these cases earlier to later.
     *
     * @param object  The object to check the state of
     * @param message Message to use for the exception, if object is not persistent
     * @throws IllegalStateException When the object is not in a persistent state
     * @see <a href="https://www.datanucleus.org/products/accessplatform_6_0/jdo/persistence.html#lifecycle">Object Lifecycle</a>
     */
    public static void assertPersistent(final Object object, final String message) {
        if (!isPersistent(object)) {
            throw new IllegalStateException(message != null ? message : "Object must be persistent");
        }
    }

    /**
     * Utility method to ensure that a given object is <strong>not</strong> in a persistent state.
     *
     * @param object  The object to check the state of
     * @param message Message to use for the exception, if object is persistent
     * @see #assertPersistent(Object, String)
     */
    public static void assertNonPersistent(final Object object, final String message) {
        if (isPersistent(object)) {
            throw new IllegalStateException(message != null ? message : "Object must not be persistent");
        }
    }

    private static boolean isPersistent(final Object object) {
        final ObjectState objectState = JDOHelper.getObjectState(object);
        return objectState == PERSISTENT_CLEAN
                || objectState == PERSISTENT_DIRTY
                || objectState == PERSISTENT_NEW
                || objectState == PERSISTENT_NONTRANSACTIONAL_DIRTY
                || objectState == HOLLOW_PERSISTENT_NONTRANSACTIONAL;
    }

}
