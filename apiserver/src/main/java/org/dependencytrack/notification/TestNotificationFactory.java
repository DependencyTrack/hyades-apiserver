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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.notification.v1.Bom;
import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Policy;
import org.dependencytrack.proto.notification.v1.PolicyCondition;
import org.dependencytrack.proto.notification.v1.PolicyViolation;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.UserSubject;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysis;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.NotificationFactory.createAnalyzerErrorNotification;
import static org.dependencytrack.notification.NotificationFactory.createBomConsumedNotification;
import static org.dependencytrack.notification.NotificationFactory.createBomProcessedNotification;
import static org.dependencytrack.notification.NotificationFactory.createBomProcessingFailedNotification;
import static org.dependencytrack.notification.NotificationFactory.createBomValidationFailedNotification;
import static org.dependencytrack.notification.NotificationFactory.createIntegrationErrorNotification;
import static org.dependencytrack.notification.NotificationFactory.createNewVulnerabilityNotification;
import static org.dependencytrack.notification.NotificationFactory.createNewVulnerableDependencyNotification;
import static org.dependencytrack.notification.NotificationFactory.createPolicyViolationNotification;
import static org.dependencytrack.notification.NotificationFactory.createProjectCreatedNotification;
import static org.dependencytrack.notification.NotificationFactory.createUserCreatedNotification;
import static org.dependencytrack.notification.NotificationFactory.createUserDeletedNotification;
import static org.dependencytrack.notification.NotificationFactory.createVexConsumedNotification;
import static org.dependencytrack.notification.NotificationFactory.createVexProcessedNotification;
import static org.dependencytrack.notification.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.notification.NotificationGroup.ANALYZER;
import static org.dependencytrack.notification.NotificationGroup.BOM_CONSUMED;
import static org.dependencytrack.notification.NotificationGroup.BOM_PROCESSED;
import static org.dependencytrack.notification.NotificationGroup.BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.NotificationGroup.BOM_VALIDATION_FAILED;
import static org.dependencytrack.notification.NotificationGroup.INTEGRATION;
import static org.dependencytrack.notification.NotificationGroup.NEW_VULNERABILITY;
import static org.dependencytrack.notification.NotificationGroup.NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.notification.NotificationGroup.POLICY_VIOLATION;
import static org.dependencytrack.notification.NotificationGroup.PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.NotificationGroup.PROJECT_CREATED;
import static org.dependencytrack.notification.NotificationGroup.USER_CREATED;
import static org.dependencytrack.notification.NotificationGroup.USER_DELETED;
import static org.dependencytrack.notification.NotificationGroup.VEX_CONSUMED;
import static org.dependencytrack.notification.NotificationGroup.VEX_PROCESSED;
import static org.dependencytrack.notification.NotificationLevel.ERROR;
import static org.dependencytrack.notification.NotificationLevel.INFORMATIONAL;
import static org.dependencytrack.notification.NotificationScope.PORTFOLIO;
import static org.dependencytrack.notification.NotificationScope.SYSTEM;

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
                            TestNotificationFactory::createVexProcessedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SYSTEM, ANALYZER, ERROR),
                            TestNotificationFactory::createAnalyzerErrorTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SYSTEM, INTEGRATION, ERROR),
                            TestNotificationFactory::createIntegrationErrorTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SYSTEM, USER_CREATED, INFORMATIONAL),
                            TestNotificationFactory::createUserCreatedTestNotification),
                    Map.entry(
                            new SupplierMatrixKey(SYSTEM, USER_DELETED, INFORMATIONAL),
                            TestNotificationFactory::createUserDeletedTestNotification));

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

    public static Notification createAnalyzerErrorTestNotification() {
        return createAnalyzerErrorNotification("failure");
    }

    public static Notification createBomConsumedTestNotification() {
        return createBomConsumedNotification(
                createProject(),
                createBom(),
                "eef2f6df-f03d-4cd4-954b-6ca1d73538e2");
    }

    public static Notification createBomProcessedTestNotification() {
        return createBomProcessedNotification(
                createProject(),
                createBom(),
                "eef2f6df-f03d-4cd4-954b-6ca1d73538e2");
    }

    public static Notification createBomProcessingFailedTestNotification() {
        return createBomProcessingFailedNotification(
                createProject(),
                createBom(),
                "eef2f6df-f03d-4cd4-954b-6ca1d73538e2",
                "cause");
    }

    public static Notification createBomValidationFailedTestNotification() {
        return createBomValidationFailedNotification(
                createProject(),
                List.of("cause 1", "cause 2"));
    }

    public static Notification createIntegrationErrorTestNotification() {
        return createIntegrationErrorNotification("failure");
    }

    public static Notification createNewVulnerabilityTestNotification() {
        return createNewVulnerabilityNotification(
                createProject(),
                createComponent(),
                createVulnerability(),
                org.dependencytrack.model.VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS.name());
    }

    public static Notification createNewVulnerableDependencyTestNotification() {
        return createNewVulnerableDependencyNotification(
                createProject(),
                createComponent(),
                List.of(createVulnerability()));
    }

    public static Notification createPolicyViolationTestNotification() {
        return createPolicyViolationNotification(
                createProject(),
                createComponent(),
                createPolicyViolation(
                        createPolicyCondition(
                                createPolicy())));
    }

    public static Notification createProjectAuditChangeTestNotification() {
        return createVulnerabilityAnalysisDecisionChangeNotification(
                createProject(),
                createComponent(),
                createVulnerability(),
                createVulnerabilityAnalysis(
                        createProject(),
                        createComponent(),
                        createVulnerability()),
                true,
                false);
    }

    public static Notification createProjectCreatedTestNotification() {
        return createProjectCreatedNotification(createProject());
    }

    public static Notification createUserCreatedTestNotification() {
        return createUserCreatedNotification(createUser());
    }

    public static Notification createUserDeletedTestNotification() {
        return createUserDeletedNotification(createUser());
    }

    public static Notification createVexConsumedTestNotification() {
        return createVexConsumedNotification(createProject(), createBom());
    }

    public static Notification createVexProcessedTestNotification() {
        return createVexProcessedNotification(createProject(), createBom());
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

    private static Policy createPolicy() {
        return Policy.newBuilder()
                .setUuid("508cf29c-0216-479d-8975-35c9c6496932")
                .setName("policyName")
                .setViolationState(org.dependencytrack.model.Policy.ViolationState.FAIL.name())
                .build();
    }

    private static PolicyCondition createPolicyCondition(final Policy policy) {
        return PolicyCondition.newBuilder()
                .setUuid("61545b13-833e-44ed-aed1-717d7e15d530")
                .setPolicy(policy)
                .setSubject(org.dependencytrack.model.PolicyCondition.Subject.PACKAGE_URL.name())
                .setOperator(org.dependencytrack.model.PolicyCondition.Operator.IS.name())
                .setValue("pkg:maven/foo/bar@1.2.3")
                .build();
    }

    private static PolicyViolation createPolicyViolation(final PolicyCondition condition) {
        return PolicyViolation.newBuilder()
                .setUuid("26ca4bdc-ca15-4aee-a4be-75d5524c3572")
                .setCondition(condition)
                .setType(org.dependencytrack.model.PolicyViolation.Type.OPERATIONAL.name())
                .setTimestamp(Timestamps.now())
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

    private static UserSubject createUser() {
        return UserSubject.newBuilder()
                .setUsername("username")
                .setEmail("username@example.com")
                .build();
    }

    private static Vulnerability createVulnerability() {
        return Vulnerability.newBuilder()
                .setUuid("bccec5d5-ec21-4958-b3e8-22a7a866a05a")
                .setVulnId("INT-001")
                .setSource(org.dependencytrack.model.Vulnerability.Source.INTERNAL.name())
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
                .setSeverity(org.dependencytrack.model.Severity.MEDIUM.name())
                .addCwes(Vulnerability.Cwe.newBuilder()
                        .setCweId(666)
                        .setName("Operation on Resource in Wrong Phase of Lifetime"))
                .addCwes(Vulnerability.Cwe.newBuilder()
                        .setCweId(777)
                        .setName("Regular Expression without Anchors"))
                .build();
    }

    private static VulnerabilityAnalysis createVulnerabilityAnalysis(
            final Project project,
            final Component component,
            final Vulnerability vulnerability) {
        return VulnerabilityAnalysis.newBuilder()
                .setProject(project)
                .setComponent(component)
                .setVulnerability(vulnerability)
                .setState(org.dependencytrack.model.AnalysisState.FALSE_POSITIVE.name())
                .setSuppressed(true)
                .build();
    }

}
