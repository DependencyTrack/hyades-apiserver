package org.dependencytrack.workflow.persistence;

import java.time.Instant;

public record WorkflowScheduleTriggerUpdate(
        long scheduleId,
        Instant nextTrigger) {
}
