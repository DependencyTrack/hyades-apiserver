package org.dependencytrack.workflow;

import alpine.common.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.job.JobContext;
import org.dependencytrack.job.JobWorker;

import java.util.Optional;
import java.util.concurrent.ExecutionException;

public class ProcessBomUploadWorkflowJobWorker implements JobWorker<JsonNode, Void> {

    private static final Logger LOGGER = Logger.getLogger(ProcessBomUploadWorkflowJobWorker.class);

    private final WorkflowEngine workflowEngine;

    ProcessBomUploadWorkflowJobWorker(final WorkflowEngine workflowEngine) {
        this.workflowEngine = workflowEngine;
    }

    public ProcessBomUploadWorkflowJobWorker() {
        this(WorkflowEngine.getInstance());
    }

    @Override
    public Optional<Void> process(final JobContext<JsonNode> jobCtx) throws Exception {
        if (jobCtx.workflowRunId() == null) {
            LOGGER.debug("Not running within the context of a workflow");
            return Optional.empty();
        }

        final WorkflowRunContext<JsonNode> workflowCtx = workflowEngine.getRunContext(jobCtx.workflowRunId());

        final JsonNode arguments = jobCtx.arguments();
        if (!arguments.has("projectUuid")) {
            LOGGER.warn("No project UUID provided");
            return Optional.empty();
        }
        if (!arguments.has("bomFilePath")) {
            LOGGER.warn("No bom file path provided");
            return Optional.empty();
        }

        try {
            workflowCtx.callActivity("ingest-bom", "123", arguments, Void.class).get();
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to ingest BOM", e.getCause());
        }

        try {
            workflowCtx.callActivity("evaluate-project-policies", "456", arguments, Void.class).get();
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to evaluate project policies", e.getCause());
        }

        try {
            workflowCtx.callActivity("update-project-metrics", "789", arguments, Void.class).get();
        } catch (ExecutionException e) {
            throw new IllegalStateException("Failed to update project metrics", e.getCause());
        }

        return Optional.empty();
    }

}
