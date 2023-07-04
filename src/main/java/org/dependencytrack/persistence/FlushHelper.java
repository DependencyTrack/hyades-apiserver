package org.dependencytrack.persistence;

import javax.jdo.PersistenceManager;

/**
 * Helper class for performing manual flushes in a long(er) {@link javax.jdo.Transaction}.
 * <p>
 * Note: Manual flushing only works when the provided {@link PersistenceManager} is using
 * {@link org.datanucleus.flush.FlushMode#MANUAL}.
 */
public final class FlushHelper implements AutoCloseable {

    private final PersistenceManager pm;
    private final int flushThreshold;
    private int numPendingChanges;

    public FlushHelper(final QueryManager qm, final int flushThreshold) {
        this(qm.getPersistenceManager(), flushThreshold);
    }

    public FlushHelper(final PersistenceManager pm, final int flushThreshold) {
        this.pm = pm;
        this.flushThreshold = flushThreshold;
    }

    /**
     * Perform a flush when this call causes the flush threshold to be reached, otherwise do nothing.
     *
     * @return {@code true} when a flush was performed, otherwise {@code false}
     */
    public boolean maybeFlush() {
        if (++numPendingChanges >= flushThreshold) {
            numPendingChanges = 0;
            pm.flush();
            return true;
        }

        return false;
    }

    /**
     * Perform a flush when there are still pending changes that haven't been flushed yet.
     *
     * @return {@code true} when a flush was performed, otherwise {@code false}
     */
    public boolean flushIfPending() {
        if (numPendingChanges > 0) {
            numPendingChanges = 0;
            pm.flush();
            return true;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        flushIfPending();
    }

}
