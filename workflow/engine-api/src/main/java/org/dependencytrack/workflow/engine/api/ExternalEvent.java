package org.dependencytrack.workflow.engine.api;

import org.dependencytrack.proto.workflow.api.v1.WorkflowPayload;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

public record ExternalEvent(
        UUID workflowRunId,
        String eventId,
        @Nullable WorkflowPayload payload) {
}
