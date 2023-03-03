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

public class ProjectMetricsUpdateTaskTest extends AbstractMetricsUpdateTaskTest {

    @Test
    public void testUpdateMetricsEmpty() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        // since no event is triggered satisfiesExactly empty is used to assert the same
        assertThat(kafkaMockProducer.history()).satisfiesExactly();
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

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        assertThat(kafkaMockProducer.history()).satisfiesExactlyInAnyOrder(
                record -> {
                    final var eventMetrics = (org.dependencytrack.model.DependencyMetrics) record.value();
                    assertThat(eventMetrics.getProject().getName()).isEqualTo("acme-app");
                    assertThat(eventMetrics.getComponent().getName()).isEqualTo("acme-lib-c");
                    assertThat(eventMetrics.getSuppressed()).isEqualTo(1);
                },
                record -> {
                    final var eventMetrics = (org.dependencytrack.model.DependencyMetrics) record.value();
                    assertThat(eventMetrics.getProject().getName()).isEqualTo("acme-app");
                    assertThat(eventMetrics.getComponent().getName()).isEqualTo("acme-lib-b");
                    assertThat(eventMetrics.getHigh()).isEqualTo(1);
                    assertThat(eventMetrics.getFindingsAudited()).isEqualTo(1);
                    assertThat(eventMetrics.getFindingsTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getInheritedRiskScore()).isEqualTo(5.0);
                    assertThat(eventMetrics.getMedium()).isZero();
                    assertThat(eventMetrics.getLow()).isZero();

                },
                record -> {
                    final var eventMetrics = (org.dependencytrack.model.DependencyMetrics) record.value();
                    assertThat(eventMetrics.getProject().getName()).isEqualTo("acme-app");
                    assertThat(eventMetrics.getComponent().getName()).isEqualTo("acme-lib-a");
                    assertThat(eventMetrics.getHigh()).isEqualTo(1);
                    assertThat(eventMetrics.getFindingsUnaudited()).isEqualTo(1);
                    assertThat(eventMetrics.getFindingsTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getInheritedRiskScore()).isEqualTo(5.0);
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

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {
                    final var eventMetrics = (org.dependencytrack.model.DependencyMetrics) record.value();
                },
                record -> {
                    final var eventMetrics = (org.dependencytrack.model.DependencyMetrics) record.value();
                    assertThat(eventMetrics.getPolicyViolationsWarn()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsAudited()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsOperationalTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);

                },
                record -> {
                    final var eventMetrics = (org.dependencytrack.model.DependencyMetrics) record.value();
                    assertThat(eventMetrics.getPolicyViolationsFail()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsUnaudited()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsLicenseTotal()).isEqualTo(1);
                    assertThat(eventMetrics.getPolicyViolationsLicenseUnaudited()).isEqualTo(1);
                }
        );
    }

    @Test
    public void testDeleteComponents() {
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
        try {
            new ProjectMetricsUpdateTask().deleteComponents(qm.getProject("acme-app", null).getUuid());
        }catch (Exception ex){
            //something
        }
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> {assertThat(record.value() == null);
                },
                record -> {assertThat(record.value() == null);
                },
                record -> {
                    assertThat(record.value() == null);
                }
        );
    }
}