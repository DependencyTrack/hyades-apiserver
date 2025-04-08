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
package org.dependencytrack.parser.dependencytrack;

import alpine.notification.NotificationLevel;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.BomValidationFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Policy;
import org.dependencytrack.proto.notification.v1.PolicyCondition;
import org.dependencytrack.proto.notification.v1.PolicyViolation;
import org.dependencytrack.proto.notification.v1.PolicyViolationAnalysis;
import org.dependencytrack.proto.notification.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysis;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.junit.Test;

import java.math.BigDecimal;
import java.sql.Date;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_ANALYZER;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_CONFIGURATION;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_DATASOURCE_MIRRORING;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_FILE_SYSTEM;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_INTEGRATION;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_POLICY_VIOLATION;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_REPOSITORY;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_WARNING;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_SYSTEM;

public class NotificationModelConverterTest extends PersistenceCapableTest {

    @Test
    public void testConvertConfigurationNotification() {
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.SYSTEM.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.CONFIGURATION.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_CONFIGURATION);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isFalse();
    }

    @Test
    public void testConvertDatasourceMirroringNotification() {
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.SYSTEM.name());
        alpineNotification.setLevel(NotificationLevel.ERROR);
        alpineNotification.setGroup(NotificationGroup.DATASOURCE_MIRRORING.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
        assertThat(notification.getGroup()).isEqualTo(GROUP_DATASOURCE_MIRRORING);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isFalse();
    }

    @Test
    public void testConvertRepositoryNotification() {
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.SYSTEM.name());
        alpineNotification.setLevel(NotificationLevel.WARNING);
        alpineNotification.setGroup(NotificationGroup.REPOSITORY.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_WARNING);
        assertThat(notification.getGroup()).isEqualTo(GROUP_REPOSITORY);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isFalse();
    }

    @Test
    public void testConvertIntegrationNotification() {
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.SYSTEM.name());
        alpineNotification.setLevel(NotificationLevel.WARNING);
        alpineNotification.setGroup(NotificationGroup.INTEGRATION.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_WARNING);
        assertThat(notification.getGroup()).isEqualTo(GROUP_INTEGRATION);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isFalse();
    }

    @Test
    public void testConvertFileSystemNotification() {
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.SYSTEM.name());
        alpineNotification.setLevel(NotificationLevel.WARNING);
        alpineNotification.setGroup(NotificationGroup.FILE_SYSTEM.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_WARNING);
        assertThat(notification.getGroup()).isEqualTo(GROUP_FILE_SYSTEM);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isFalse();
    }

    @Test
    public void testConvertAnalyzerNotification() {
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.SYSTEM.name());
        alpineNotification.setLevel(NotificationLevel.WARNING);
        alpineNotification.setGroup(NotificationGroup.ANALYZER.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_SYSTEM);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_WARNING);
        assertThat(notification.getGroup()).isEqualTo(GROUP_ANALYZER);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isFalse();
    }

    @Test
    public void testConvertNewVulnerabilityNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final org.dependencytrack.model.Component component = createComponent(project);
        final org.dependencytrack.model.Vulnerability vulnerability = createVulnerability();

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.NEW_VULNERABILITY.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new NewVulnerabilityIdentified(vulnerability, component,
                VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_NEW_VULNERABILITY);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(NewVulnerabilitySubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(NewVulnerabilitySubject.class);
        assertComponent(subject.getComponent());
        assertProject(subject.getProject());
        assertVulnerability(subject.getVulnerability());
        assertThat(subject.getAffectedProjectsReference().getApiUri())
                .isEqualTo("/api/v1/vulnerability/source/INTERNAL/vuln/INT-001/projects");
        assertThat(subject.getAffectedProjectsReference().getFrontendUri())
                .isEqualTo("/vulnerabilities/INTERNAL/INT-001/affectedProjects");
        assertThat(subject.getVulnerabilityAnalysisLevel()).isEqualTo("BOM_UPLOAD_ANALYSIS");
        assertThat(subject.getAffectedProjectsList()).satisfiesExactly(this::assertProject);
    }

    @Test
    public void testConvertNewVulnerableDependencyNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final org.dependencytrack.model.Component component = createComponent(project);
        final org.dependencytrack.model.Vulnerability vulnerability = createVulnerability();

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.NEW_VULNERABLE_DEPENDENCY.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new NewVulnerableDependency(component, Set.of(vulnerability)));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_NEW_VULNERABLE_DEPENDENCY);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(NewVulnerableDependencySubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(NewVulnerableDependencySubject.class);
        assertComponent(subject.getComponent());
        assertProject(subject.getProject());
        assertThat(subject.getVulnerabilitiesList()).satisfiesExactly(this::assertVulnerability);
    }

    @Test
    public void testConvertVulnerabilityAnalysisDecisionChangeNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final org.dependencytrack.model.Component component = createComponent(project);
        final org.dependencytrack.model.Vulnerability vulnerability = createVulnerability();
        final org.dependencytrack.model.Analysis analysis = createVulnerabilityAnalysis(vulnerability, component);

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new AnalysisDecisionChange(vulnerability, component, project, analysis));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(VulnerabilityAnalysisDecisionChangeSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(VulnerabilityAnalysisDecisionChangeSubject.class);
        assertComponent(subject.getComponent());
        assertProject(subject.getProject());
        assertVulnerability(subject.getVulnerability());
        assertVulnerabilityAnalysis(subject.getAnalysis());
    }

    @Test
    public void testConvertPolicyViolationAnalysisDecisionChangeNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final org.dependencytrack.model.Component component = createComponent(project);
        final org.dependencytrack.model.Policy policy = createPolicy();
        final org.dependencytrack.model.PolicyCondition policyCondition = createPolicyCondition(policy);
        final org.dependencytrack.model.PolicyViolation policyViolation = createPolicyViolation(policyCondition, component);
        final org.dependencytrack.model.ViolationAnalysis analysis = createPolicyViolationAnalysis(policyViolation, component);

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new ViolationAnalysisDecisionChange(policyViolation, component, analysis));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(PolicyViolationAnalysisDecisionChangeSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(PolicyViolationAnalysisDecisionChangeSubject.class);
        assertComponent(subject.getComponent());
        assertProject(subject.getProject());
        assertPolicyViolation(subject.getPolicyViolation());
        assertPolicyViolationAnalysis(subject.getAnalysis());
    }

    @Test
    public void testConvertBomConsumedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final var token = UUID.randomUUID();
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.BOM_CONSUMED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new BomConsumedOrProcessed(token, project, "bom", Bom.Format.CYCLONEDX, "1.4"));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(BomConsumedOrProcessedSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(BomConsumedOrProcessedSubject.class);
        assertProject(subject.getProject());
        assertThat(subject.getToken()).isEqualTo(token.toString());
        assertThat(subject.getBom().getContent()).isEqualTo("bom");
        assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
        assertThat(subject.getBom().getSpecVersion()).isEqualTo("1.4");
    }

    @Test
    public void testConvertBomProcessedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final var token = UUID.randomUUID();
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.BOM_PROCESSED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new BomConsumedOrProcessed(token, project, "bom", Bom.Format.CYCLONEDX, "1.4"));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(BomConsumedOrProcessedSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(BomConsumedOrProcessedSubject.class);
        assertProject(subject.getProject());
        assertThat(subject.getToken()).isEqualTo(token.toString());
        assertThat(subject.getBom().getContent()).isEqualTo("bom");
        assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
        assertThat(subject.getBom().getSpecVersion()).isEqualTo("1.4");
    }

    @Test
    public void testConvertBomProcessingFailedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final var token = UUID.randomUUID();
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.ERROR);
        alpineNotification.setGroup(NotificationGroup.BOM_PROCESSING_FAILED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new BomProcessingFailed(token, project, "bom", "just because", Bom.Format.CYCLONEDX, "1.4"));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
        assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(BomProcessingFailedSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(BomProcessingFailedSubject.class);
        assertProject(subject.getProject());
        assertThat(subject.getToken()).isEqualTo(token.toString());
        assertThat(subject.getBom().getContent()).isEqualTo("bom");
        assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
        assertThat(subject.getBom().getSpecVersion()).isEqualTo("1.4");
        assertThat(subject.getCause()).isEqualTo("just because");
    }

    @Test
    public void testConvertBomValidationFailedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.ERROR);
        alpineNotification.setGroup(NotificationGroup.BOM_VALIDATION_FAILED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new BomValidationFailed(project, "bom", List.of("just because")));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
        assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_VALIDATION_FAILED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(BomValidationFailedSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(BomValidationFailedSubject.class);
        assertProject(subject.getProject());
        assertThat(subject.getBom().getContent()).isEqualTo("bom");
        assertThat(subject.getErrors(0)).isEqualTo("just because");
    }

    @Test
    public void testConvertVexConsumedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.VEX_CONSUMED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new VexConsumedOrProcessed(project, "bom", Vex.Format.CYCLONEDX, "1.4"));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_VEX_CONSUMED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(VexConsumedOrProcessedSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(VexConsumedOrProcessedSubject.class);
        assertProject(subject.getProject());
        assertThat(subject.getVex().toStringUtf8()).isEqualTo("bom");
        assertThat(subject.getFormat()).isEqualTo("CycloneDX");
        assertThat(subject.getSpecVersion()).isEqualTo("1.4");
    }

    @Test
    public void testConvertVexProcessedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.VEX_PROCESSED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new VexConsumedOrProcessed(project, "bom", Vex.Format.CYCLONEDX, "1.4"));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_VEX_PROCESSED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(VexConsumedOrProcessedSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(VexConsumedOrProcessedSubject.class);
        assertProject(subject.getProject());
        assertThat(subject.getVex().toStringUtf8()).isEqualTo("bom");
        assertThat(subject.getFormat()).isEqualTo("CycloneDX");
        assertThat(subject.getSpecVersion()).isEqualTo("1.4");
    }

    @Test
    public void testConvertPolicyViolationNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();
        final org.dependencytrack.model.Component component = createComponent(project);
        final org.dependencytrack.model.Policy policy = createPolicy();
        final org.dependencytrack.model.PolicyCondition policyCondition = createPolicyCondition(policy);
        final org.dependencytrack.model.PolicyViolation policyViolation = createPolicyViolation(policyCondition, component);

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.POLICY_VIOLATION.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(new PolicyViolationIdentified(policyViolation, component, project));

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_POLICY_VIOLATION);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(PolicyViolationSubject.class)).isTrue();

        final var subject = notification.getSubject().unpack(PolicyViolationSubject.class);
        assertComponent(subject.getComponent());
        assertProject(subject.getProject());
        assertPolicyViolation(subject.getPolicyViolation());
    }

    @Test
    public void testConvertProjectCreatedNotification() throws Exception {
        final org.dependencytrack.model.Project project = createProject();

        final var alpineNotification = new alpine.notification.Notification();
        alpineNotification.setScope(NotificationScope.PORTFOLIO.name());
        alpineNotification.setLevel(NotificationLevel.INFORMATIONAL);
        alpineNotification.setGroup(NotificationGroup.PROJECT_CREATED.name());
        alpineNotification.setTitle("Foo");
        alpineNotification.setContent("Bar");
        alpineNotification.setSubject(project);

        final Notification notification = NotificationModelConverter.convert(alpineNotification);
        assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
        assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_CREATED);
        assertThat(notification.getTitle()).isEqualTo("Foo");
        assertThat(notification.getContent()).isEqualTo("Bar");
        assertThat(notification.getTimestamp().getSeconds()).isNotZero();
        assertThat(notification.hasSubject()).isTrue();
        assertThat(notification.getSubject().is(Project.class)).isTrue();

        final var subject = notification.getSubject().unpack(Project.class);
        assertProject(subject);
    }

    private org.dependencytrack.model.Project createProject() {
        final var projectTag1 = new Tag();
        projectTag1.setName("tag1");
        final var projectTag2 = new Tag();
        projectTag2.setName("tag2");

        final var project = new org.dependencytrack.model.Project();
        project.setUuid(UUID.fromString("0957687b-3482-4891-a836-dad37e9b804a"));
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setDescription("projectDescription");
        project.setPurl("pkg:maven/org.acme/acme-app@projectVersion");
        project.setTags(List.of(projectTag1, projectTag2));
        return project;
    }

    private void assertProject(final Project project) {
        assertThat(project.getUuid()).isEqualTo("0957687b-3482-4891-a836-dad37e9b804a");
        assertThat(project.getName()).isEqualTo(project.getName());
        assertThat(project.getVersion()).isEqualTo(project.getVersion());
        assertThat(project.getDescription()).isEqualTo(project.getDescription());
        assertThat(project.getPurl()).isEqualTo("pkg:maven/org.acme/acme-app@projectVersion");
        assertThat(project.getTagsList()).containsOnly("tag1", "tag2");
    }

    private org.dependencytrack.model.Component createComponent(final org.dependencytrack.model.Project project) {
        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("3c87b90d-d08a-492a-855e-d6e9d8b63a18"));
        component.setName("componentName");
        component.setVersion("componentVersion");
        return component;
    }

    private void assertComponent(final Component component) {
        assertThat(component.getUuid()).isEqualTo("3c87b90d-d08a-492a-855e-d6e9d8b63a18");
        assertThat(component.getName()).isEqualTo("componentName");
        assertThat(component.getVersion()).isEqualTo("componentVersion");
    }

    private org.dependencytrack.model.Vulnerability createVulnerability() {
        final var alias = new org.dependencytrack.model.VulnerabilityAlias();
        alias.setInternalId("INT-001");
        alias.setOsvId("OSV-001");

        final var vuln = new org.dependencytrack.model.Vulnerability();
        vuln.setUuid(UUID.fromString("418d9be1-f888-446a-8f03-f3253e5b5361"));
        vuln.setVulnId("INT-001");
        vuln.setSource(org.dependencytrack.model.Vulnerability.Source.INTERNAL);
        vuln.setAliases(List.of(alias));
        vuln.setTitle("vulnerabilityTitle");
        vuln.setSubTitle("vulnerabilitySubTitle");
        vuln.setDescription("vulnerabilityDescription");
        vuln.setRecommendation("vulnerabilityRecommendation");
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(5.5));
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(6.6));
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(1.1));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(2.2));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.3));
        vuln.setSeverity(Severity.MEDIUM);
        vuln.setCwes(List.of(666, 777));
        return vuln;
    }

    private void assertVulnerability(final Vulnerability vuln) {
        assertThat(vuln.getUuid()).isEqualTo("418d9be1-f888-446a-8f03-f3253e5b5361");
        assertThat(vuln.getVulnId()).isEqualTo("INT-001");
        assertThat(vuln.getSource()).isEqualTo("INTERNAL");
        assertThat(vuln.getAliasesList()).satisfiesExactly(
                alias -> {
                    assertThat(alias.getId()).isEqualTo("OSV-001");
                    assertThat(alias.getSource()).isEqualTo("OSV");
                }
        );
        assertThat(vuln.getTitle()).isEqualTo("vulnerabilityTitle");
        assertThat(vuln.getSubTitle()).isEqualTo("vulnerabilitySubTitle");
        assertThat(vuln.getDescription()).isEqualTo("vulnerabilityDescription");
        assertThat(vuln.getRecommendation()).isEqualTo("vulnerabilityRecommendation");
        assertThat(vuln.getCvssV2()).isEqualTo(5.5);
        assertThat(vuln.getCvssV3()).isEqualTo(6.6);
        assertThat(vuln.getOwaspRrLikelihood()).isEqualTo(1.1);
        assertThat(vuln.getOwaspRrTechnicalImpact()).isEqualTo(2.2);
        assertThat(vuln.getOwaspRrBusinessImpact()).isEqualTo(3.3);
        assertThat(vuln.getSeverity()).isEqualTo("MEDIUM");
        assertThat(vuln.getCwesList()).satisfiesExactly(
                cwe -> {
                    assertThat(cwe.getCweId()).isEqualTo(666);
                    assertThat(cwe.getName()).isEqualTo("Operation on Resource in Wrong Phase of Lifetime");
                },
                cwe -> {
                    assertThat(cwe.getCweId()).isEqualTo(777);
                    assertThat(cwe.getName()).isEqualTo("Regular Expression without Anchors");
                }
        );
    }

    private Analysis createVulnerabilityAnalysis(final org.dependencytrack.model.Vulnerability vuln,
                                                 final org.dependencytrack.model.Component component) {
        final var analysis = new org.dependencytrack.model.Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.FALSE_POSITIVE);
        analysis.setSuppressed(true);
        return analysis;
    }

    private void assertVulnerabilityAnalysis(final VulnerabilityAnalysis analysis) {
        assertComponent(analysis.getComponent());
        assertProject(analysis.getProject());
        assertVulnerability(analysis.getVulnerability());
        assertThat(analysis.getState()).isEqualTo("FALSE_POSITIVE");
        assertThat(analysis.getSuppressed()).isTrue();
    }

    private ViolationAnalysis createPolicyViolationAnalysis(final org.dependencytrack.model.PolicyViolation policyViolation,
                                                            final org.dependencytrack.model.Component component) {
        final var analysis = new org.dependencytrack.model.ViolationAnalysis();
        analysis.setComponent(component);
        analysis.setPolicyViolation(policyViolation);
        analysis.setViolationAnalysisState(ViolationAnalysisState.REJECTED);
        analysis.setSuppressed(true);
        return analysis;
    }

    private void assertPolicyViolationAnalysis(final PolicyViolationAnalysis analysis) {
        assertComponent(analysis.getComponent());
        assertProject(analysis.getProject());
        assertPolicyViolation(analysis.getPolicyViolation());
        assertThat(analysis.getState()).isEqualTo("REJECTED");
        assertThat(analysis.getSuppressed()).isTrue();
    }

    private org.dependencytrack.model.Policy createPolicy() {
        final var policy = new org.dependencytrack.model.Policy();
        policy.setUuid(UUID.fromString("dbab0e47-b32a-45e8-b2f8-89e3f45d7516"));
        policy.setName("policyName");
        policy.setViolationState(org.dependencytrack.model.Policy.ViolationState.FAIL);
        return policy;
    }

    private void assertPolicy(final Policy policy) {
        assertThat(policy.getUuid()).isEqualTo("dbab0e47-b32a-45e8-b2f8-89e3f45d7516");
        assertThat(policy.getName()).isEqualTo("policyName");
        assertThat(policy.getViolationState()).isEqualTo("FAIL");
    }

    private org.dependencytrack.model.PolicyCondition createPolicyCondition(final org.dependencytrack.model.Policy policy) {
        final var policyCondition = new org.dependencytrack.model.PolicyCondition();
        policyCondition.setUuid(UUID.fromString("203578b9-eb6f-4704-8586-bd386a0c4793"));
        policyCondition.setPolicy(policy);
        policyCondition.setSubject(org.dependencytrack.model.PolicyCondition.Subject.COORDINATES);
        policyCondition.setOperator(org.dependencytrack.model.PolicyCondition.Operator.MATCHES);
        policyCondition.setValue("policyConditionValue");
        return policyCondition;
    }

    private void assertPolicyCondition(final PolicyCondition policyCondition) {
        assertThat(policyCondition.getUuid()).isEqualTo("203578b9-eb6f-4704-8586-bd386a0c4793");
        assertPolicy(policyCondition.getPolicy());
        assertThat(policyCondition.getSubject()).isEqualTo("COORDINATES");
        assertThat(policyCondition.getOperator()).isEqualTo("MATCHES");
        assertThat(policyCondition.getValue()).isEqualTo("policyConditionValue");
    }

    private org.dependencytrack.model.PolicyViolation createPolicyViolation(final org.dependencytrack.model.PolicyCondition policyCondition,
                                                                            final org.dependencytrack.model.Component component) {
        final var policyViolation = new org.dependencytrack.model.PolicyViolation();
        policyViolation.setUuid(UUID.fromString("3ee0eb3e-9076-4a98-8460-997e8b3a5d59"));
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setComponent(component);
        policyViolation.setType(org.dependencytrack.model.PolicyViolation.Type.OPERATIONAL);
        policyViolation.setTimestamp(Date.from(Instant.ofEpochSecond(1679326314)));
        return policyViolation;
    }

    private void assertPolicyViolation(final PolicyViolation policyViolation) {
        assertThat(policyViolation.getUuid()).isEqualTo("3ee0eb3e-9076-4a98-8460-997e8b3a5d59");
        assertPolicyCondition(policyViolation.getCondition());
        assertThat(policyViolation.getType()).isEqualTo("OPERATIONAL");
        assertThat(policyViolation.getTimestamp().getSeconds()).isEqualTo(1679326314);
    }

}