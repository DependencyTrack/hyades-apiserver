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

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class Workflows {

    public static final List<WorkflowSpec> ALL_WORKFLOWS;
    public static final WorkflowSpec WORKFLOW_BOM_UPLOAD_PROCESSING_V1;
    public static final WorkflowSpec WORKFLOW_PROJECT_VULNERABILITY_ANALYSIS_V1;

    static {
        WORKFLOW_BOM_UPLOAD_PROCESSING_V1 = new WorkflowSpec(
                "bom-upload-processing",
                /* version */ 1,
                List.of(
                        new WorkflowStepSpec(
                                "consume-bom",
                                WorkflowStepType.JOB,
                                Collections.emptySet()),
                        new WorkflowStepSpec(
                                "process-bom",
                                WorkflowStepType.JOB,
                                Set.of("consume-bom")),
                        new WorkflowStepSpec(
                                "analyze-vulns-project",
                                WorkflowStepType.JOB,
                                Set.of("process-bom")),
                        new WorkflowStepSpec(
                                "evaluate-policies-project",
                                WorkflowStepType.JOB,
                                Set.of("analyze-vulns-project")),
                        new WorkflowStepSpec(
                                "update-metrics-project",
                                WorkflowStepType.JOB,
                                Set.of("evaluate-policies-project"))));

        WORKFLOW_PROJECT_VULNERABILITY_ANALYSIS_V1 = new WorkflowSpec(
                "project-vuln-analysis",
                /* version */ 1,
                List.of(
                        new WorkflowStepSpec(
                                "analyze-vulns-project",
                                WorkflowStepType.JOB,
                                Collections.emptySet()),
                        new WorkflowStepSpec(
                                "update-metrics-project",
                                WorkflowStepType.JOB,
                                Set.of("analyze-vulns-project"))));

        ALL_WORKFLOWS = List.of(
                WORKFLOW_BOM_UPLOAD_PROCESSING_V1,
                WORKFLOW_PROJECT_VULNERABILITY_ANALYSIS_V1);
    }

}
