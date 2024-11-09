package org.dependencytrack.workflow.model;

import java.util.UUID;

public record ScheduleWorkflowOptions(
        String name,
        String cron,
        String workflowName,
        int workflowVersion,
        Integer priority,
        UUID uniqueKey,
        byte[] arguments) {
}
