package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.collections4.ListUtils;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.WorkflowStateReaperEvent;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.Query;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.dependencytrack.tasks.LockName.WORKFLOW_STEP_REAPER_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.executeWithLock;

public class WorkflowStateReaperTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(WorkflowStateReaperTask.class);

    private final Duration retentionDuration;

    public WorkflowStateReaperTask() {
        this(Duration.parse(Config.getInstance().getProperty(ConfigKey.WORKFLOW_RETENTION_DURATION)));
    }

    WorkflowStateReaperTask(final Duration retentionDuration) {
        this.retentionDuration = retentionDuration;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof WorkflowStateReaperEvent) {
            final Date threshold = Date.from(Instant.now().minus(retentionDuration));

            executeWithLock(WORKFLOW_STEP_REAPER_TASK_LOCK, (Runnable) () -> {
                try (final var qm = new QueryManager()) {
                    transitionToTimedOut(qm, threshold);
                    transitionToFailed(qm, threshold);
                    deleteExpiredWorkflows(qm, threshold);
                }
            });
        }
    }

    /**
     * Transition steps to {@link WorkflowStatus#TIMED_OUT}, if:
     * - they have been started
     * - their state is non-terminal, and
     * - they have not been updated for the threshold time frame
     * <p>
     * Because {@link WorkflowStatus#TIMED_OUT} states can still eventually become {@link WorkflowStatus#COMPLETED}
     * or {@link WorkflowStatus#FAILED}, child steps do not have to be cancelled.
     * <p>
     * TODO: Change this to Bulk Update query once https://github.com/datanucleus/datanucleus-rdbms/issues/474
     *   is resolved. Fetching all records and updating them individually is SUPER inefficient.
     *
     * @param qm        The {@link QueryManager} to use
     * @param threshold The threshold to enforce
     */
    private static void transitionToTimedOut(final QueryManager qm, final Date threshold) {

        final Query<WorkflowState> timeoutQuery = qm.getPersistenceManager().newQuery(WorkflowState.class);
        timeoutQuery.setFilter("status == :status && startedAt != null && updatedAt < :threshold");
        timeoutQuery.setNamedParameters(Map.of(
                "threshold", threshold,
                "status", WorkflowStatus.PENDING
        ));
        try {
            int stepsTimedOut = 0;
            for (final WorkflowState state : timeoutQuery.executeList()) {
                qm.runInTransaction(() -> {
                    state.setStatus(WorkflowStatus.TIMED_OUT);
                    state.setUpdatedAt(new Date());
                });
                stepsTimedOut++;
            }
            LOGGER.info("Transitioned %d workflow steps to %s state"
                    .formatted(stepsTimedOut, WorkflowStatus.TIMED_OUT));
        } finally {
            timeoutQuery.closeAll();
        }
    }

    /**
     * Transition states to FAILED, if their status is TIMED_OUT,
     * and they have not been updated for the threshold time frame.
     *
     * @param qm        The {@link QueryManager} to use
     * @param threshold The threshold to enforce
     */
    private static void transitionToFailed(final QueryManager qm, final Date threshold) {

        final Query<WorkflowState> failedQuery = qm.getPersistenceManager().newQuery(WorkflowState.class);
        failedQuery.setFilter("status == :timedOutStatus && updatedAt < :threshold");
        failedQuery.setNamedParameters(Map.of(
                "timedOutStatus", WorkflowStatus.TIMED_OUT,
                "threshold", threshold
        ));
        try {
            int stepsFailed = 0;
            int stepsCancelled = 0;
            for (final WorkflowState state : failedQuery.executeList()) {
                stepsCancelled += qm.runInTransaction(() -> {
                    state.setStatus(WorkflowStatus.FAILED);
                    state.setFailureReason("Timed out");
                    state.setUpdatedAt(new Date());

                    // TODO: Changing the status should also update updatedAt
                    return qm.updateAllDescendantStatesOfParent(state, WorkflowStatus.CANCELLED);
                });
                stepsFailed++;
            }
            LOGGER.info("Transitioned %d workflow steps to %s state, and cancelled %d follow-up steps"
                    .formatted(stepsFailed, WorkflowStatus.FAILED, stepsCancelled));
        } finally {
            failedQuery.closeAll();
        }
    }

    /**
     * @param qm        The {@link QueryManager} to use
     * @param threshold The threshold to enforce
     */
    private static void deleteExpiredWorkflows(final QueryManager qm, final Date threshold) {
        final Query<WorkflowState> deletableWorkflowsQuery = qm.getPersistenceManager().newQuery(WorkflowState.class);
        deletableWorkflowsQuery.setFilter("!:nonTerminalStatuses.contains(status) && updatedAt < :threshold");
        deletableWorkflowsQuery.setNamedParameters(Map.of(
                "nonTerminalStatuses", Set.of(WorkflowStatus.PENDING, WorkflowStatus.TIMED_OUT),
                "threshold", threshold
        ));
        deletableWorkflowsQuery.setResult("DISTINCT token");
        final List<UUID> tokens;
        try {
            tokens = List.copyOf(deletableWorkflowsQuery.executeResultList(UUID.class));
        } finally {
            deletableWorkflowsQuery.closeAll();
        }

        // Bulk delete workflows in batches of up to 50 UUIDs in order to keep the query size manageable.
        final List<List<UUID>> tokenBatches = ListUtils.partition(tokens, 100);
        for (final List<UUID> tokenBatch : tokenBatches) {
            final Query<?> workflowDeleteQuery = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                    DELETE FROM org.dependencytrack.model.WorkflowState
                    WHERE :tokens.contains(token)
                    """);
            try {
                final long stepsDeleted = qm.runInTransaction(() -> (long) workflowDeleteQuery.execute(tokenBatch));
                LOGGER.info("Deleted %d workflow steps".formatted(stepsDeleted));
            } finally {
                workflowDeleteQuery.closeAll();
            }
        }
    }

}
