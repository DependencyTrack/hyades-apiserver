package org.dependencytrack.workflow.api;

import org.jspecify.annotations.Nullable;

/**
 * {@link Error} that may be thrown during a workflow execution.
 * <p>
 * Errors of this type <strong>must not</strong> be caught,
 * as they are expected to be handled by the engine.
 */
public abstract sealed class WorkflowRunError extends Error permits
        WorkflowRunBlockedError,
        WorkflowRunCanceledError,
        WorkflowRunContinuedAsNewError,
        WorkflowRunDeterminismError {

    WorkflowRunError(@Nullable final String message) {
        super(message);
    }

    WorkflowRunError(
            @Nullable final String message,
            @Nullable final Throwable cause,
            final boolean enableSuppression,
            final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
