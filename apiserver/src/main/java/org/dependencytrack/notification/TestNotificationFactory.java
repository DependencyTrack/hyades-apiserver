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
package org.dependencytrack.notification;

import alpine.notification.NotificationLevel;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import org.dependencytrack.proto.notification.v1.BackReference;
import org.dependencytrack.proto.notification.v1.Bom;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysis;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static alpine.notification.NotificationLevel.ERROR;
import static alpine.notification.NotificationLevel.INFORMATIONAL;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.NotificationFactory.newNotificationBuilder;
import static org.dependencytrack.notification.NotificationGroup.BOM_CONSUMED;
import static org.dependencytrack.notification.NotificationGroup.BOM_PROCESSED;
import static org.dependencytrack.notification.NotificationGroup.BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.NotificationGroup.BOM_VALIDATION_FAILED;
import static org.dependencytrack.notification.NotificationGroup.NEW_VULNERABILITY;
import static org.dependencytrack.notification.NotificationGroup.NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.notification.NotificationGroup.POLICY_VIOLATION;
import static org.dependencytrack.notification.NotificationGroup.PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.NotificationGroup.PROJECT_CREATED;
import static org.dependencytrack.notification.NotificationGroup.VEX_CONSUMED;
import static org.dependencytrack.notification.NotificationGroup.VEX_PROCESSED;
import static org.dependencytrack.notification.NotificationScope.PORTFOLIO;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_POLICY_VIOLATION;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;

/**
 * Factory for test notifications.
 * <p>
 * TODO: Should eventually be moved to plugin-api so that it
 *  can be re-used for publisher plugin tests.
 *
 * @since 5.7.0
 */
public final class TestNotificationFactory {

    private record SupplierMatrixKey(
            NotificationScope scope,
            NotificationGroup group,
            NotificationLevel level) {

        private SupplierMatrixKey {
            requireNonNull(level, "level must not be null");
            requireNonNull(scope, "scope must not be null");
            requireNonNull(group, "group must not be null");
        }

    }

    private static final Map<SupplierMatrixKey, Supplier<Notification>> SUPPLIER_MATRIX =
            Map.ofEntries(
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, BOM_CONSUMED, INFORMATIONAL),
                            TestNotificationFactory::createBomConsumedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, BOM_PROCESSED, INFORMATIONAL),
                            TestNotificationFactory::createBomProcessedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, BOM_PROCESSING_FAILED, ERROR),
                            TestNotificationFactory::createBomProcessingFailedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, BOM_VALIDATION_FAILED, ERROR),
                            TestNotificationFactory::createBomValidationFailedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, NEW_VULNERABILITY, INFORMATIONAL),
                            TestNotificationFactory::createNewVulnerabilityTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, NEW_VULNERABLE_DEPENDENCY, INFORMATIONAL),
                            TestNotificationFactory::createNewVulnerableDependencyTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, POLICY_VIOLATION, INFORMATIONAL),
                            TestNotificationFactory::createPolicyViolationTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, PROJECT_AUDIT_CHANGE, INFORMATIONAL),
                            TestNotificationFactory::createProjectAuditChangeTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, PROJECT_CREATED, INFORMATIONAL),
                            TestNotificationFactory::createProjectCreatedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, VEX_CONSUMED, INFORMATIONAL),
                            TestNotificationFactory::createVexConsumedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(PORTFOLIO, VEX_PROCESSED, INFORMATIONAL),
                            TestNotificationFactory::createVexProcessedTestNotification));

    private TestNotificationFactory() {
    }

    public static Notification createTestNotification(
            final NotificationScope scope,
            final NotificationGroup group,
            final NotificationLevel level) {
        final Supplier<Notification> supplier =
                SUPPLIER_MATRIX.get(new SupplierMatrixKey(scope, group, level));
        if (supplier != null) {
            return supplier.get();
        }

        return null;
    }

    public static Notification createBomConsumedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.BOM_CONSUMED)
                .setContent("A CycloneDX BOM was consumed and will be processed")
                .setSubject(Any.pack(
                        BomConsumedOrProcessedSubject.newBuilder()
                                .setProject(createProject())
                                .setBom(createBom())
                                .build()))
                .build();
    }

    public static Notification createBomProcessedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.BOM_PROCESSED)
                .setContent("A CycloneDX BOM was processed")
                .setSubject(Any.pack(
                        BomConsumedOrProcessedSubject.newBuilder()
                                .setProject(createProject())
                                .setBom(createBom())
                                .build()))
                .build();
    }

    public static Notification createBomProcessingFailedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSING_FAILED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                .setContent("An error occurred while processing a BOM")
                .setSubject(Any.pack(
                        BomProcessingFailedSubject.newBuilder()
                                .setProject(createProject())
                                .setBom(createBom())
                                .setCause("cause")
                                .build()))
                .build();
    }

    public static Notification createBomValidationFailedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_VALIDATION_FAILED, LEVEL_ERROR)
                .setTitle(NotificationConstants.Title.BOM_VALIDATION_FAILED)
                .setContent("An error occurred while validating a BOM")
                .setSubject(Any.pack(
                        BomValidationFailedSubject.newBuilder()
                                .setProject(createProject())
                                .setBom(createBom())
                                .addErrors("cause 1")
                                .addErrors("cause 2")
                                .build()))
                .build();
    }

    public static Notification createNewVulnerabilityTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABILITY, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.NEW_VULNERABILITY)
                .setContent("Vulnerability description")
                .setSubject(Any.pack(
                        NewVulnerabilitySubject.newBuilder()
                                .setComponent(createComponent())
                                .setProject(createProject())
                                .setVulnerability(createVulnerability())
                                .setVulnerabilityAnalysisLevel("BOM_UPLOAD_ANALYSIS")
                                .addAffectedProjects(createProject())
                                .setAffectedProjectsReference(BackReference.newBuilder()
                                        .setApiUri("/api/v1/vulnerability/source/INTERNAL/vuln/INT-001/projects")
                                        .setFrontendUri("/vulnerabilities/INTERNAL/INT-001/affectedProjects"))
                                .build()))
                .build();
    }

    public static Notification createNewVulnerableDependencyTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABLE_DEPENDENCY, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY)
                .setContent("A dependency was introduced that contains 1 known vulnerability")
                .setSubject(Any.pack(
                        NewVulnerableDependencySubject.newBuilder()
                                .setComponent(createComponent())
                                .setProject(createProject())
                                .addVulnerabilities(createVulnerability())
                                .build()))
                .build();
    }

    public static Notification createPolicyViolationTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_POLICY_VIOLATION, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.POLICY_VIOLATION)
                .setContent("A security policy violation occurred")
                .setSubject(Any.pack(
                        PolicyViolationSubject.newBuilder()
                                .setProject(createProject())
                                .setComponent(createComponent())
                                .build()))
                .build();
    }

    public static Notification createProjectAuditChangeTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_AUDIT_CHANGE, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED)
                .setContent("An analysis decision was made to a finding affecting a project")
                .setSubject(Any.pack(
                        VulnerabilityAnalysisDecisionChangeSubject.newBuilder()
                                .setProject(createProject())
                                .setComponent(createComponent())
                                .setVulnerability(createVulnerability())
                                .setAnalysis(createVulnerabilityAnalysis())
                                .build()))
                .build();
    }

    public static Notification createProjectCreatedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_CREATED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.PROJECT_CREATED)
                .setContent("projectName was created")
                .setSubject(Any.pack(createProject()))
                .build();
    }

    public static Notification createVexConsumedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_VEX_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.VEX_CONSUMED)
                .setContent("A CycloneDX VEX was consumed and will be processed")
                .setSubject(Any.pack(
                        VexConsumedOrProcessedSubject.newBuilder()
                                .setProject(createProject())
                                .setFormat("CycloneDX")
                                .setSpecVersion("1.5")
                                .setVex(ByteString.copyFromUtf8("vexContent"))
                                .build()))
                .build();
    }

    public static Notification createVexProcessedTestNotification() {
        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_VEX_PROCESSED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.VEX_PROCESSED)
                .setContent("A CycloneDX VEX was processed")
                .setSubject(Any.pack(
                        VexConsumedOrProcessedSubject.newBuilder()
                                .setProject(createProject())
                                .setFormat("CycloneDX")
                                .setSpecVersion("1.5")
                                .setVex(ByteString.copyFromUtf8("vexContent"))
                                .build()))
                .build();
    }

    private static Bom createBom() {
        return Bom.newBuilder()
                .setContent("bomContent")
                .setFormat("CycloneDX")
                .setSpecVersion("1.5")
                .build();
    }

    private static Component createComponent() {
        return Component.newBuilder()
                .setUuid("94f87321-a5d1-4c2f-b2fe-95165debebc6")
                .setName("componentName")
                .setVersion("componentVersion")
                .build();
    }

    private static Project createProject() {
        return Project.newBuilder()
                .setUuid("c9c9539a-e381-4b36-ac52-6a7ab83b2c95")
                .setName("projectName")
                .setVersion("projectVersion")
                .setDescription("projectDescription")
                .setPurl("pkg:maven/org.acme/projectName@projectVersion")
                .addAllTags(List.of("tag1", "tag2"))
                .setIsActive(true)
                .build();
    }

    private static Vulnerability createVulnerability() {
        return Vulnerability.newBuilder()
                .setUuid("bccec5d5-ec21-4958-b3e8-22a7a866a05a")
                .setVulnId("INT-001")
                .setSource("INTERNAL")
                .addAliases(Vulnerability.Alias.newBuilder()
                        .setId("OSV-001")
                        .setSource("OSV")
                        .build())
                .setTitle("vulnerabilityTitle")
                .setSubTitle("vulnerabilitySubTitle")
                .setDescription("vulnerabilityDescription")
                .setRecommendation("vulnerabilityRecommendation")
                .setCvssV2(5.5)
                .setCvssV3(6.6)
                .setOwaspRrLikelihood(1.1)
                .setOwaspRrTechnicalImpact(2.2)
                .setOwaspRrBusinessImpact(3.3)
                .setSeverity("MEDIUM")
                .addCwes(Vulnerability.Cwe.newBuilder()
                        .setCweId(666)
                        .setName("Operation on Resource in Wrong Phase of Lifetime"))
                .addCwes(Vulnerability.Cwe.newBuilder()
                        .setCweId(777)
                        .setName("Regular Expression without Anchors"))
                .build();
    }

    private static VulnerabilityAnalysis createVulnerabilityAnalysis() {
        return VulnerabilityAnalysis.newBuilder()
                .setProject(createProject())
                .setComponent(createComponent())
                .setVulnerability(createVulnerability())
                .setState("FALSE_POSITIVE")
                .setSuppressed(true)
                .build();
    }

}
