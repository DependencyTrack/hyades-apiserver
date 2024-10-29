/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.workflow;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.job.JobManager;
import org.junit.Test;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.workflow.Workflows.WORKFLOW_BOM_UPLOAD_PROCESSING_V1;

public class WorkflowEngineTest extends PersistenceCapableTest {

    @Test
    public void foo() throws Exception {
        final var workflowEngine = WorkflowEngine.getInstance();
        workflowEngine.deploy(WORKFLOW_BOM_UPLOAD_PROCESSING_V1);

        final var jobManager = JobManager.getInstance();
        jobManager.registerStatusListener(workflowEngine);

        try {
            final var countDownLatch = new CountDownLatch(1000);
            jobManager.registerWorker(Set.of("consume-bom"), job -> {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                return Optional.empty();
            }, 10);
            jobManager.registerWorker(Set.of("process-bom"), job -> {
                countDownLatch.countDown();
                return Optional.empty();
            }, 1);

            for (int i = 0; i < 1000; i++) {
                workflowEngine.startWorkflow(new StartWorkflowOptions(
                        WORKFLOW_BOM_UPLOAD_PROCESSING_V1.name(),
                        WORKFLOW_BOM_UPLOAD_PROCESSING_V1.version()));
            }

            await("foo")
                    .atMost(360, TimeUnit.SECONDS)
                    .until(() -> countDownLatch.getCount() == 0);
        } finally {
            jobManager.close();
            workflowEngine.close();
        }
    }

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
        assertThat(workflowRun.status()).isEqualTo(WorkflowRunStatus.PENDING);
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