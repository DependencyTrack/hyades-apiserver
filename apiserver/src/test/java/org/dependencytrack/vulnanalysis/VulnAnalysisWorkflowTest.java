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
package org.dependencytrack.vulnanalysis;

import io.github.resilience4j.core.IntervalFunction;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStoragePlugin;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.policy.cel.CelVulnerabilityPolicyEvaluator;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerArg;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerRes;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisArg;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisRes;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowArg;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.internal.InternalVulnAnalyzerPlugin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;

class VulnAnalysisWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest
            = new WorkflowTestExtension(postgresContainer);

    private PluginManager pluginManager;

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder()
                        .withDefaultValue("dt.vuln-analyzer.internal.datasource.name", "default")
                        .build(),
                secretName -> null,
                List.of(FileStorage.class, VulnAnalyzer.class));
        pluginManager.loadPlugins(List.of(
                new MemoryFileStoragePlugin(),
                new InternalVulnAnalyzerPlugin()));

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new VulnAnalysisWorkflow(),
                protoConverter(VulnAnalysisWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new DeleteFilesActivity(pluginManager),
                protoConverter(DeleteFilesArgument.class),
                voidConverter(),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new InvokeVulnAnalyzerActivity(pluginManager),
                protoConverter(InvokeVulnAnalyzerArg.class),
                protoConverter(InvokeVulnAnalyzerRes.class),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new PrepareVulnAnalysisActivity(pluginManager),
                protoConverter(PrepareVulnAnalysisArg.class),
                protoConverter(PrepareVulnAnalysisRes.class),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new ReconcileVulnAnalysisResultsActivity(
                        pluginManager,
                        new CelVulnerabilityPolicyEvaluator()),
                protoConverter(ReconcileVulnAnalysisResultsArg.class),
                voidConverter(),
                Duration.ofSeconds(5));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "vuln-analyses", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-vuln-analysis", "vuln-analyses", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void test() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.fasterxml.jackson.core");
        vs.setPurlName("jackson-databind");
        vs.setVersionStartIncluding("2.9.0");
        vs.setVersionEndExcluding("3");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.9.8");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
        qm.persist(component);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final List<Vulnerability> vulns = qm.getVulnerabilities(project, true);
        assertThat(vulns).hasSize(1);
    }

}