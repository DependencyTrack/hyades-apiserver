package org.dependencytrack.workflow.persistence;

import org.dependencytrack.workflow.model.WorkflowRunStatus;

import java.time.Instant;
import java.util.UUID;

public record WorkflowRunUpdate(
        UUID id,
        WorkflowRunStatus status,
        String result,
        String failureDetails,
        Instant updatedAt,
        Instant endedAt) {
}
