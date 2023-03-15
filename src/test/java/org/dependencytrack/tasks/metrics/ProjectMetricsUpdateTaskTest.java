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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.metrics;

import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;
import static org.hyades.proto.metrics.v1.Status.STATUS_UNKNOWN;

public class ProjectMetricsUpdateTaskTest extends AbstractMetricsUpdateTaskTest {

    @Test
    public void testUpdateMetricsEmpty() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        // since no event is triggered satisfiesExactly empty is used to assert the same
        assertThat(kafkaMockProducer.history()).isEmpty();
    }

    @Test
    public void testUpdateMetricsVulnerabilities() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        // Create a component with an unaudited vulnerability.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, AnalyzerIdentity.NONE);

        // Create a project with an audited vulnerability.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        qm.addVulnerability(vuln, componentAudited, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentAudited, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a project with a suppressed vulnerability.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        qm.addVulnerability(vuln, componentSuppressed, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentSuppressed, vuln, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        final Project finalProject = project;
        final Component finalComponentUnaudited = componentUnaudited;
        final Component finalComponentAudited = componentAudited;
        final Component finalComponentSuppressed = componentSuppressed;

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        assertThat(kafkaMockProducer.history()).satisfiesExactlyInAnyOrder(
                record -> {
                    final var eventMetrics = deserializeValue(KafkaTopics.COMPONENT_METRICS, record);
                    assertThat(eventMetrics.getProjectUuid()).isEqualTo(finalProject.getUuid().toString());
                    assertThat(eventMetrics.getComponentUuid()).isEqualTo(finalComponentSuppressed.getUuid().toString());
                    assertThat(eventMetrics.getStatus()).isEqualTo(STATUS_UNKNOWN);
                    assertThat(eventMetrics.getInheritedRiskScore()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getCritical()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getHigh()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getMedium()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getLow()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getUnassigned()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getSuppressed()).isEqualTo(1);
                },
                record -> {
                    final var eventMetrics = deserializeValue(KafkaTopics.COMPONENT_METRICS, record);
                    assertThat(eventMetrics.getProjectUuid()).isEqualTo(finalProject.getUuid().toString());
                    assertThat(eventMetrics.getComponentUuid()).isEqualTo(finalComponentAudited.getUuid().toString());
                    assertThat(eventMetrics.getStatus()).isEqualTo(STATUS_UNKNOWN);
                    assertThat(eventMetrics.getInheritedRiskScore()).isEqualTo(5.0);
                    assertThat(eventMetrics.getVulnerabilities().getTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getVulnerabilities().getCritical()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getHigh()).isEqualTo(1);
                    assertThat(eventMetrics.getVulnerabilities().getMedium()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getLow()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getUnassigned()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getFindings().getAudited()).isEqualTo(1);
                    assertThat(eventMetrics.getFindings().getUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getSuppressed()).isEqualTo(0);
                },
                record -> {
                    final var eventMetrics = deserializeValue(KafkaTopics.COMPONENT_METRICS, record);
                    assertThat(eventMetrics.getProjectUuid()).isEqualTo(finalProject.getUuid().toString());
                    assertThat(eventMetrics.getComponentUuid()).isEqualTo(finalComponentUnaudited.getUuid().toString());
                    assertThat(eventMetrics.getStatus()).isEqualTo(STATUS_UNKNOWN);
                    assertThat(eventMetrics.getInheritedRiskScore()).isEqualTo(5.0);
                    assertThat(eventMetrics.getVulnerabilities().getTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getVulnerabilities().getCritical()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getHigh()).isEqualTo(1);
                    assertThat(eventMetrics.getVulnerabilities().getMedium()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getLow()).isEqualTo(0);
                    assertThat(eventMetrics.getVulnerabilities().getUnassigned()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getFindings().getAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getFindings().getUnaudited()).isEqualTo(1);
                    assertThat(eventMetrics.getFindings().getSuppressed()).isEqualTo(0);
                }
        );
    }

    @Test
    public void testUpdateMetricsPolicyViolations() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        // Create a component with an unaudited violation.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, Policy.ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a component with an audited violation.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, Policy.ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(componentAudited, violationAudited, ViolationAnalysisState.APPROVED, false);

        // Create a component with a suppressed violation.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, Policy.ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(componentSuppressed, violationSuppressed, ViolationAnalysisState.REJECTED, true);

        final Project finalProject = project;
        final Component finalComponentUnaudited = componentUnaudited;
        final Component finalComponentAudited = componentAudited;
        final Component finalComponentSuppressed = componentSuppressed;

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    final var eventMetrics = deserializeValue(KafkaTopics.COMPONENT_METRICS, record);
                    assertThat(eventMetrics.getProjectUuid()).isEqualTo(finalProject.getUuid().toString());
                    assertThat(eventMetrics.getComponentUuid()).isEqualTo(finalComponentSuppressed.getUuid().toString());
                    assertThat(eventMetrics.getPolicyViolations().getTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getFail()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getWarn()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getInfo()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityUnaudited()).isEqualTo(0);
                },
                record -> {
                    final var eventMetrics = deserializeValue(KafkaTopics.COMPONENT_METRICS, record);
                    assertThat(eventMetrics.getProjectUuid()).isEqualTo(finalProject.getUuid().toString());
                    assertThat(eventMetrics.getComponentUuid()).isEqualTo(finalComponentAudited.getUuid().toString());
                    assertThat(eventMetrics.getPolicyViolations().getTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getFail()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getWarn()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getInfo()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getAudited()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalAudited()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityUnaudited()).isEqualTo(0);

                },
                record -> {
                    final var eventMetrics = deserializeValue(KafkaTopics.COMPONENT_METRICS, record);
                    assertThat(eventMetrics.getProjectUuid()).isEqualTo(finalProject.getUuid().toString());
                    assertThat(eventMetrics.getComponentUuid()).isEqualTo(finalComponentUnaudited.getUuid().toString());
                    assertThat(eventMetrics.getPolicyViolations().getTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getFail()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getWarn()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getInfo()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getUnaudited()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getLicenseUnaudited()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getOperationalUnaudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityTotal()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityAudited()).isEqualTo(0);
                    assertThat(eventMetrics.getPolicyViolations().getSecurityUnaudited()).isEqualTo(0);
                }
        );
    }

    @Test
    public void testDeleteComponents() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        // Create a component with an unaudited vulnerability.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, AnalyzerIdentity.NONE);

        // Create a project with an audited vulnerability.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        qm.addVulnerability(vuln, componentAudited, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentAudited, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a project with a suppressed vulnerability.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        qm.addVulnerability(vuln, componentSuppressed, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentSuppressed, vuln, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        ProjectMetricsUpdateTask.deleteComponents(project.getUuid());

        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.value()).isNull(),
                record -> assertThat(record.value()).isNull(),
                record -> assertThat(record.value()).isNull(),
                record -> assertThat(record.value()).isNull()
        );
    }
}