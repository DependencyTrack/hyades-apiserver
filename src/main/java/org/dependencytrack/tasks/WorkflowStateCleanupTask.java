package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.collections4.ListUtils;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.WorkflowStateCleanupEvent;
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

import static org.apache.commons.lang3.time.DateFormatUtils.ISO_8601_EXTENDED_DATETIME_FORMAT;
import static org.dependencytrack.tasks.LockName.WORKFLOW_STEP_CLEANUP_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.executeWithLock;

public class WorkflowStateCleanupTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(WorkflowStateCleanupTask.class);

    private final Duration stepTimeoutDuration;
    private final Duration retentionDuration;


    @SuppressWarnings("unused") // Called by Alpine's event system
    public WorkflowStateCleanupTask() {
        this(
                Duration.parse(Config.getInstance().getProperty(ConfigKey.WORKFLOW_STEP_TIMEOUT_DURATION)),
                Duration.parse(Config.getInstance().getProperty(ConfigKey.WORKFLOW_RETENTION_DURATION))
        );
    }

    WorkflowStateCleanupTask(final Duration stepTimeoutDuration, final Duration retentionDuration) {
        this.stepTimeoutDuration = stepTimeoutDuration;
        this.retentionDuration = retentionDuration;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof WorkflowStateCleanupEvent) {
            final Instant now = Instant.now();
            final Date timeoutCutoff = Date.from(now.minus(stepTimeoutDuration));
            final Date retentionCutoff = Date.from(now.minus(retentionDuration));

            executeWithLock(WORKFLOW_STEP_CLEANUP_TASK_LOCK, (Runnable) () -> {
                try (final var qm = new QueryManager()) {
                    transitionPendingStepsToTimedOut(qm, timeoutCutoff);
                    transitionTimedOutStepsToFailed(qm, timeoutCutoff);
                    deleteExpiredWorkflows(qm, retentionCutoff);
                }
            });
        }
    }

    /**
     * Transition steps to {@link WorkflowStatus#TIMED_OUT}, if:
     * - their state is non-terminal, and
     * - they have not been updated for the threshold time frame
     * <p>
     * Because {@link WorkflowStatus#TIMED_OUT} states can still eventually become {@link WorkflowStatus#COMPLETED}
     * or {@link WorkflowStatus#FAILED}, child steps do not have to be cancelled.
     * <p>
     * TODO: Change this to bulk update query once https://github.com/datanucleus/datanucleus-rdbms/issues/474
     *   is resolved. Fetching all records and updating them individually is SUPER inefficient.
     *
     * @param qm            The {@link QueryManager} to use
     * @param timeoutCutoff The timeout cutoff
     */
    private static void transitionPendingStepsToTimedOut(final QueryManager qm, final Date timeoutCutoff) {
        final Query<WorkflowState> timeoutQuery = qm.getPersistenceManager().newQuery(WorkflowState.class);
        timeoutQuery.setFilter("status == :status && updatedAt < :cutoff");
        timeoutQuery.setNamedParameters(Map.of(
                "status", WorkflowStatus.PENDING,
                "cutoff", timeoutCutoff
        ));
        int stepsTimedOut = 0;
        try {
            for (final WorkflowState state : timeoutQuery.executeList()) {
                qm.runInTransaction(() -> {
                    state.setStatus(WorkflowStatus.TIMED_OUT);
                    state.setUpdatedAt(new Date());
                });
                stepsTimedOut++;
            }
        } finally {
            timeoutQuery.closeAll();
        }

        if (stepsTimedOut > 0) {
            LOGGER.warn("Transitioned %d workflow steps to %s state".formatted(stepsTimedOut, WorkflowStatus.TIMED_OUT));
        } else {
            LOGGER.info("No workflow steps to transition to %s state".formatted(WorkflowStatus.TIMED_OUT));
        }
    }

    /**
     * Transition states to {@link WorkflowStatus#FAILED}, if their current status is {@link WorkflowStatus#TIMED_OUT},
     * and they have not been updated for the threshold time frame.
     *
     * @param qm            The {@link QueryManager} to use
     * @param timeoutCutoff The timeout cutoff
     */
    private static void transitionTimedOutStepsToFailed(final QueryManager qm, final Date timeoutCutoff) {
        final Query<WorkflowState> failedQuery = qm.getPersistenceManager().newQuery(WorkflowState.class);
        failedQuery.setFilter("status == :status && updatedAt < :cutoff");
        failedQuery.setNamedParameters(Map.of(
                "status", WorkflowStatus.TIMED_OUT,
                "cutoff", timeoutCutoff
        ));
        int stepsFailed = 0;
        int stepsCancelled = 0;
        try {
            for (final WorkflowState state : failedQuery.executeList()) {
                stepsCancelled += qm.runInTransaction(() -> {
                    final Date now = new Date();
                    state.setStatus(WorkflowStatus.FAILED);
                    state.setFailureReason("Timed out");
                    state.setUpdatedAt(now);
                    return qm.updateAllDescendantStatesOfParent(state, WorkflowStatus.CANCELLED, now);
                });
                stepsFailed++;
            }
        } finally {
            failedQuery.closeAll();
        }

        if (stepsFailed > 0) {
            LOGGER.warn("Transitioned %d %s workflow steps to %s status, and cancelled %d follow-up steps"
                    .formatted(stepsFailed, WorkflowStatus.TIMED_OUT, WorkflowStatus.FAILED, stepsCancelled));
        } else {
            LOGGER.info("No %s workflow steps to transition to %s status"
                    .formatted(WorkflowStatus.TIMED_OUT, WorkflowStatus.FAILED));
        }
    }

    /**
     * Delete all {@link WorkflowState}s grouped by the same {@code token}, given all of their
     * steps are in a terminal state, and their last update timestamp falls below {@code retentionCutoff}.
     *
     * @param qm              The {@link QueryManager} to use
     * @param retentionCutoff The retention cutoff time
     */
    private static void deleteExpiredWorkflows(final QueryManager qm, final Date retentionCutoff) {
        // Find all workflow tokens for which the most recently updated step falls below the
        // retention cutoff time.
        // TODO: There's likely a better way to do this. What we really want is all tokens where
        //   all steps' statuses are terminal, and "max(updatedAt) < :cutoff" is true. In JDO,
        //   the HAVING clause can only contain aggregates, but not individual fields, and we
        //   cannot aggregate the status field.
        final Query<?> deletionCandidatesQuery = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                SELECT token FROM org.dependencytrack.model.WorkflowState
                GROUP BY token
                HAVING max(updatedAt) < :cutoff
                """);
        deletionCandidatesQuery.setNamedParameters(Map.of(
                "cutoff", retentionCutoff
        ));
        final List<UUID> deletableWorkflows;
        try {
            deletableWorkflows = List.copyOf(deletionCandidatesQuery.executeResultList(UUID.class));
        } finally {
            deletionCandidatesQuery.closeAll();
        }

        // Bulk delete workflows based on the previously collected tokens.
        // Do so in batches of up to 100 tokens in order to keep the query size manageable.
        // Workflows are only deleted when all of their steps are in a terminal status.
        long stepsDeleted = 0;
        final List<List<UUID>> tokenBatches = ListUtils.partition(deletableWorkflows, 100);
        for (final List<UUID> tokenBatch : tokenBatches) {
            final Query<?> workflowDeleteQuery = qm.getPersistenceManager().newQuery(Query.JDOQL, """
                    DELETE FROM org.dependencytrack.model.WorkflowState
                    WHERE :tokens.contains(token) && (
                        SELECT FROM org.dependencytrack.model.WorkflowState w
                            WHERE w.token == this.token && :nonTerminalStatuses.contains(w.status)
                    ).isEmpty()
                    """);
            try {
                stepsDeleted += qm.runInTransaction(() -> (long) workflowDeleteQuery.executeWithMap(Map.of(
                        "tokens", tokenBatch,
                        "nonTerminalStatuses", Set.of(WorkflowStatus.PENDING, WorkflowStatus.TIMED_OUT)
                )));
            } finally {
                workflowDeleteQuery.closeAll();
            }
        }

        if (stepsDeleted > 0) {
            LOGGER.info("Deleted %d workflow steps falling below retention cutoff %s"
                    .formatted(stepsDeleted, ISO_8601_EXTENDED_DATETIME_FORMAT.format(retentionCutoff)));
        } else {
            LOGGER.info("No workflows to delete for retention cutoff %s"
                    .formatted(ISO_8601_EXTENDED_DATETIME_FORMAT.format(retentionCutoff)));
        }
    }

}
