package org.dependencytrack.workflow.model;

public record ScheduleWorkflowOptions(
        String name,
        String cron,
        String workflowName,
        int workflowVersion,
        Integer priority,
        byte[] arguments) {
}
