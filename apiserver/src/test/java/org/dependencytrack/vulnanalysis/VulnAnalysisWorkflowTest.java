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
import org.dependencytrack.cache.api.NoopCacheManager;
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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.dependencytrack.persistence.jdbi.FindingDao.FindingRow;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.policy.cel.CelVulnerabilityPolicyEvaluator;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyRating;
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

import java.math.BigDecimal;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class VulnAnalysisWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest
            = new WorkflowTestExtension(postgresContainer);

    private PluginManager pluginManager;

    @BeforeEach
    void beforeEach() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder()
                        .withDefaultValue("dt.vuln-analyzer.internal.datasource.name", "default")
                        .build(),
                new NoopCacheManager(),
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

        final var vs = new VulnerableSoftware();
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

        final var component = new Component();
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

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getGroup()).isEqualTo(GROUP_NEW_VULNERABILITY);
        });
    }

    @Test
    void shouldDeactivateFindingsThatAreNoLongerReported() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        final long projectId = project.getId();
        final Supplier<List<FindingRow>> findingsSupplier = () -> withJdbiHandle(
                handle -> handle
                        .attach(FindingDao.class)
                        .getFindingsByProject(
                                projectId,
                                /* includeInactive */ false,
                                /* includeSuppressed */ false,
                                null));

        List<FindingRow> findings = findingsSupplier.get();
        assertThat(findings).hasSize(1);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        findings = findingsSupplier.get();
        assertThat(findings).isEmpty();

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void analysisThroughPolicyNewAnalysisTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-100");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        policyAnalysis.setVendorResponse(VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX);
        policyAnalysis.setDetails("Policy details");

        final var cvssV3Rating = new VulnerabilityPolicyRating();
        cvssV3Rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV3);
        cvssV3Rating.setVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        cvssV3Rating.setScore(3.7);
        cvssV3Rating.setSeverity(VulnerabilityPolicyRating.Severity.LOW);

        createPolicy("testPolicy", "testAuthor",
                List.of("has(component.name)", "project.version != \"\""),
                policyAnalysis, List.of(cvssV3Rating));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
            assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("Policy details");
            assertThat(analysis.isSuppressed()).isFalse();
            assertThat(analysis.getSeverity()).isEqualTo(Severity.LOW);
            assertThat(analysis.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
            assertThat(analysis.getCvssV3Score()).isEqualByComparingTo("3.7");
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            """
                                    Matched on condition(s):
                                    - has(component.name)
                                    - project.version != \"\"""",
                            "Analysis: NOT_SET → NOT_AFFECTED",
                            "Justification: NOT_SET → CODE_NOT_REACHABLE",
                            "Vendor Response: NOT_SET → WILL_NOT_FIX",
                            "Details: Policy details",
                            "Severity: UNASSIGNED → LOW",
                            "CVSSv3 Vector: (None) → CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                            "CVSSv3 Score: (None) → 3.7");
        });

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactlyInAnyOrder(
                        GROUP_NEW_VULNERABILITY,
                        GROUP_PROJECT_AUDIT_CHANGE);
    }

    @Test
    void analysisThroughPolicyNewAnalysisSuppressionTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-101");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);
        policyAnalysis.setSuppress(true);

        final var cvssV4Rating = new VulnerabilityPolicyRating();
        cvssV4Rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV4);
        cvssV4Rating.setVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
        cvssV4Rating.setScore(0.0);
        cvssV4Rating.setSeverity(VulnerabilityPolicyRating.Severity.LOW);

        createPolicy("suppressPolicy", "testAuthor",
                List.of("true"),
                policyAnalysis, List.of(cvssV4Rating));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.FALSE_POSITIVE);
            assertThat(analysis.isSuppressed()).isTrue();
            assertThat(analysis.getSeverity()).isEqualTo(Severity.LOW);
            assertThat(analysis.getCvssV4Vector()).isEqualTo("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
            assertThat(analysis.getCvssV4Score()).isEqualByComparingTo("0.0");
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            """
                                    Matched on condition(s):
                                    - true""",
                            "Analysis: NOT_SET → FALSE_POSITIVE",
                            "Suppressed",
                            "Severity: UNASSIGNED → LOW",
                            "CVSSv4 Vector: (None) → CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                            "CVSSv4 Score: (None) → 0.0");
        });

        // Suppressed finding should NOT generate a NEW_VULNERABILITY notification,
        // but should still generate a PROJECT_AUDIT_CHANGE notification.
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification ->
                assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE));
    }

    @Test
    void analysisThroughPolicyExistingDifferentAnalysisTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-102");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        // Pre-create analysis with different values than the policy will set.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.IN_TRIAGE)
                        .withJustification(AnalysisJustification.NOT_SET)
                        .withResponse(AnalysisResponse.NOT_SET)
                        .withDetails("old details")
                        .withSuppress(false)
                        .withOptions(Set.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        policyAnalysis.setVendorResponse(VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX);
        policyAnalysis.setDetails("new details");
        policyAnalysis.setSuppress(true);

        final var cvssV3Rating = new VulnerabilityPolicyRating();
        cvssV3Rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV3);
        cvssV3Rating.setVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        cvssV3Rating.setScore(3.7);
        cvssV3Rating.setSeverity(VulnerabilityPolicyRating.Severity.LOW);

        createPolicy("updatePolicy", "testAuthor",
                List.of("has(component.name)"),
                policyAnalysis, List.of(cvssV3Rating));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
            assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("new details");
            assertThat(analysis.isSuppressed()).isTrue();
            assertThat(analysis.getSeverity()).isEqualTo(Severity.LOW);
            assertThat(analysis.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
            assertThat(analysis.getCvssV3Score()).isEqualByComparingTo("3.7");
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            """
                                    Matched on condition(s):
                                    - has(component.name)""",
                            "Analysis: IN_TRIAGE → NOT_AFFECTED",
                            "Justification: NOT_SET → CODE_NOT_REACHABLE",
                            "Vendor Response: NOT_SET → WILL_NOT_FIX",
                            "Details: new details",
                            "Suppressed",
                            "Severity: UNASSIGNED → LOW",
                            "CVSSv3 Vector: (None) → CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                            "CVSSv3 Score: (None) → 3.7");
        });

        // Existing finding should not trigger NEW_VULNERABILITY notification,
        // but state and suppression changed, so PROJECT_AUDIT_CHANGE should be emitted.
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification ->
                assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE));
    }

    @Test
    void analysisThroughPolicyExistingEqualAnalysisTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-103");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        // Pre-create analysis with values that exactly match the policy.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withSuppress(false)
                        .withOptions(Set.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);

        createPolicy("matchingPolicy", "testAuthor",
                List.of("true"),
                policyAnalysis, null);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisComments()).isEmpty();
        });
    }

    @Test
    void analysisThroughPolicyWithPoliciesNotYetValidOrNotValidAnymoreTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-104");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        // Policy with validFrom in the future.
        final var futureAnalysis = new VulnerabilityPolicyAnalysis();
        futureAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);

        final var futurePolicy = new VulnerabilityPolicy();
        futurePolicy.setName("futurePolicy");
        futurePolicy.setConditions(List.of("true"));
        futurePolicy.setAnalysis(futureAnalysis);
        futurePolicy.setValidFrom(ZonedDateTime.now().plusDays(30));
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(futurePolicy));

        // Policy with validUntil in the past.
        final var expiredAnalysis = new VulnerabilityPolicyAnalysis();
        expiredAnalysis.setState(VulnerabilityPolicyAnalysis.State.RESOLVED);

        final var expiredPolicy = new VulnerabilityPolicy();
        expiredPolicy.setName("expiredPolicy");
        expiredPolicy.setConditions(List.of("true"));
        expiredPolicy.setAnalysis(expiredAnalysis);
        expiredPolicy.setValidUntil(ZonedDateTime.now().minusDays(30));
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(expiredPolicy));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).isNull();
    }

    @Test
    void analysisThroughPolicyWithAnalysisUpdateNotOnStateOrSuppressionTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-105");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        // Pre-create analysis with same state/suppressed as policy but different details.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withDetails("old details")
                        .withSuppress(false)
                        .withOptions(Set.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setDetails("new details");

        createPolicy("detailsPolicy", "testAuthor",
                List.of("true"),
                policyAnalysis, null);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("new details");
            assertThat(analysis.isSuppressed()).isFalse();
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            """
                                    Matched on condition(s):
                                    - true""",
                            "Details: new details");
        });

        // No state or suppression change, so no NEW_VULNERABILITY or PROJECT_AUDIT_CHANGE.
        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void analysisThroughPolicyWithPoliciesLoggableTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-106");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);

        final var policy = new VulnerabilityPolicy();
        policy.setName("logPolicy");
        policy.setConditions(List.of("true"));
        policy.setAnalysis(policyAnalysis);
        policy.setOperationMode(VulnerabilityPolicyOperation.LOG);
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(policy));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).isNull();
    }

    @Test
    void analysisThroughPolicyResetOnNoMatchTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        component.setProject(project);
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);
        policyAnalysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        policyAnalysis.setVendorResponse(VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX);
        policyAnalysis.setSuppress(true);
        final var policy = new VulnerabilityPolicy();
        policy.setName("Foo");
        policy.setConditions(List.of("component.name == \"some-other-name\""));
        policy.setAnalysis(policyAnalysis);
        policy.setOperationMode(VulnerabilityPolicyOperation.APPLY);
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(policy));

        // Create vulnerability with existing analysis that was previously applied by the above policy,
        // but is no longer current.
        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setSeverity(Severity.CRITICAL);
        qm.persist(vulnA);
        qm.addVulnerability(vulnA, component, "internal");
        final var analysisA = new Analysis();
        analysisA.setComponent(component);
        analysisA.setVulnerability(vulnA);
        analysisA.setAnalysisState(AnalysisState.NOT_AFFECTED);
        analysisA.setAnalysisJustification(AnalysisJustification.CODE_NOT_REACHABLE);
        analysisA.setAnalysisResponse(AnalysisResponse.WILL_NOT_FIX);
        analysisA.setAnalysisDetails("Because I say so.");
        analysisA.setSeverity(Severity.MEDIUM);
        analysisA.setCvssV2Vector("oldCvssV2Vector");
        analysisA.setCvssV2Score(BigDecimal.valueOf(1.1));
        analysisA.setCvssV3Vector("oldCvssV3Vector");
        analysisA.setCvssV3Score(BigDecimal.valueOf(2.2));
        analysisA.setOwaspVector("oldOwaspVector");
        analysisA.setOwaspScore(BigDecimal.valueOf(3.3));
        analysisA.setCvssV4Vector("oldCvssV4Vector");
        analysisA.setCvssV4Score(BigDecimal.valueOf(4.4));
        analysisA.setSuppressed(true);
        qm.persist(analysisA);
        useJdbiHandle(jdbiHandle -> jdbiHandle.createUpdate("""
                        UPDATE
                          "ANALYSIS"
                        SET
                          "VULNERABILITY_POLICY_ID" = (SELECT "ID" FROM "VULNERABILITY_POLICY" WHERE "NAME" = :vulnPolicyName)
                        WHERE
                          "ID" = :analysisId
                        """)
                .bind("vulnPolicyName", policy.getName())
                .bind("analysisId", analysisA.getId())
                .execute());

        // Create another vulnerability with existing analysis that was manually applied.
        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        vulnB.setSeverity(Severity.HIGH);
        qm.persist(vulnB);
        qm.addVulnerability(vulnB, component, "internal");
        final var analysisB = new Analysis();
        analysisB.setComponent(component);
        analysisB.setVulnerability(vulnB);
        analysisB.setAnalysisState(AnalysisState.NOT_AFFECTED);
        qm.persist(analysisB);

        // Ensure that CVE-100 and CVE-200 will still be reported.
        final var vsVulnA = new VulnerableSoftware();
        vsVulnA.setPurlType("maven");
        vsVulnA.setPurlNamespace("com.example");
        vsVulnA.setPurlName("acme-lib");
        vsVulnA.setVersionStartIncluding("1.0.0");
        vsVulnA.setVersionEndExcluding("2.0.0");
        vsVulnA.setVulnerable(true);
        vsVulnA.addVulnerability(vulnA);
        qm.persist(vsVulnA);
        final var vsB = new VulnerableSoftware();
        vsB.setPurlType("maven");
        vsB.setPurlNamespace("com.example");
        vsB.setPurlName("acme-lib");
        vsB.setVersionStartIncluding("1.0.0");
        vsB.setVersionEndExcluding("2.0.0");
        vsB.setVulnerable(true);
        vsB.addVulnerability(vulnB);
        qm.persist(vsB);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();

        // The analysis that was previously applied via policy must have been reverted.
        assertThat(qm.getAnalysis(component, vulnA)).satisfies(a -> {
            assertThat(a.getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
            assertThat(a.getVulnerabilityPolicyId()).isNull();
            assertThat(a.isSuppressed()).isFalse();
            assertThat(a.getAnalysisComments())
                    .extracting(AnalysisComment::getCommenter)
                    .containsOnly("[Policy{None}]");
            assertThat(a.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactlyInAnyOrder(
                            "No longer covered by any policy",
                            "Analysis: NOT_AFFECTED → NOT_SET",
                            "Justification: CODE_NOT_REACHABLE → NOT_SET",
                            "Vendor Response: WILL_NOT_FIX → NOT_SET",
                            "Details: (None)",
                            "Severity: MEDIUM → UNASSIGNED",
                            "CVSSv2 Vector: oldCvssV2Vector → (None)",
                            "CVSSv2 Score: 1.1 → (None)",
                            "CVSSv3 Vector: oldCvssV3Vector → (None)",
                            "CVSSv3 Score: 2.2 → (None)",
                            "OWASP Vector: oldOwaspVector → (None)",
                            "OWASP Score: 3.3 → (None)",
                            "CVSSv4 Vector: oldCvssV4Vector → (None)",
                            "CVSSv4 Score: 4.4 → (None)",
                            "Unsuppressed");
        });

        // The manually applied analysis must not be touched.
        assertThat(qm.getAnalysis(component, vulnB)).satisfies(a -> {
            assertThat(a.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(a.getVulnerabilityPolicyId()).isNull();
            assertThat(a.getAnalysisComments()).isEmpty();
        });
    }

    private static void createPolicy(
            String name,
            String author,
            List<String> conditions,
            VulnerabilityPolicyAnalysis analysis,
            List<VulnerabilityPolicyRating> ratings) {
        final var policy = new VulnerabilityPolicy();
        policy.setName(name);
        policy.setAuthor(author);
        policy.setConditions(conditions);
        policy.setAnalysis(analysis);
        policy.setRatings(ratings);
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(policy));
    }

}
