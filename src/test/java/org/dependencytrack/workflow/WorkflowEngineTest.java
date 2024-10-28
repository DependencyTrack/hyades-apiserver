package org.dependencytrack.workflow;

import org.dependencytrack.PersistenceCapableTest;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.workflow.Workflows.WORKFLOW_BOM_UPLOAD_PROCESSING_V1;

public class WorkflowEngineTest extends PersistenceCapableTest {

    @Test
    public void test() {
        final var manager = WorkflowEngine.getInstance();
        manager.deploy(WORKFLOW_BOM_UPLOAD_PROCESSING_V1);

        final WorkflowRunView workflowRun = manager.startWorkflow(new StartWorkflowOptions(
                WORKFLOW_BOM_UPLOAD_PROCESSING_V1.name(),
                WORKFLOW_BOM_UPLOAD_PROCESSING_V1.version()));

        assertThat(workflowRun.workflowName()).isEqualTo("bom-upload-processing");
        assertThat(workflowRun.workflowVersion()).isEqualTo(1);
        assertThat(workflowRun.token()).isNotNull();
        assertThat(workflowRun.status()).isEqualTo(WorkflowRunStatus.NEW);
        assertThat(workflowRun.createdAt()).isNotNull();
        assertThat(workflowRun.startedAt()).isNull();
        assertThat(workflowRun.steps()).satisfiesExactlyInAnyOrder(
                step -> {
                    assertThat(step.stepName()).isEqualTo("consume-bom");
                    assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                    assertThat(step.createdAt()).isNotNull();
                    assertThat(step.startedAt()).isNull();
                },
                step -> {
                    assertThat(step.stepName()).isEqualTo("process-bom");
                    assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                    assertThat(step.createdAt()).isNotNull();
                    assertThat(step.startedAt()).isNull();
                },
                step -> {
                    assertThat(step.stepName()).isEqualTo("analyze-vulns");
                    assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                    assertThat(step.createdAt()).isNotNull();
                    assertThat(step.startedAt()).isNull();
                },
                step -> {
                    assertThat(step.stepName()).isEqualTo("evaluate-policies");
                    assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                    assertThat(step.createdAt()).isNotNull();
                    assertThat(step.startedAt()).isNull();
                },
                step -> {
                    assertThat(step.stepName()).isEqualTo("update-metrics");
                    assertThat(step.status()).isEqualTo(WorkflowStepRunStatus.PENDING);
                    assertThat(step.createdAt()).isNotNull();
                    assertThat(step.startedAt()).isNull();
                });
    }

}