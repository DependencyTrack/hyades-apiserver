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
package org.dependencytrack.notification.api;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochRandomGenerator;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.notification.proto.v1.BackReference;
import org.dependencytrack.notification.proto.v1.Bom;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.notification.proto.v1.BomValidationFailedSubject;
import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.ComponentVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.Group;
import org.dependencytrack.notification.proto.v1.Level;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.PolicyViolation;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysis;
import org.dependencytrack.notification.proto.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.notification.proto.v1.PolicyViolationSubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisStatus;
import org.dependencytrack.notification.proto.v1.Scope;
import org.dependencytrack.notification.proto.v1.UserSubject;
import org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysis;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jspecify.annotations.Nullable;

import java.util.Collection;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_ANALYZER;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_INTEGRATION;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_POLICY_VIOLATION;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_VULN_ANALYSIS_COMPLETE;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_UNSPECIFIED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_USER_CREATED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_USER_DELETED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VEX_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_UNSPECIFIED;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_SYSTEM;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_UNSPECIFIED;

/**
 * Factory for notifications that the platform may emit.
 *
 * @since 5.7.0
 */
public final class NotificationFactory {

    private static final TimeBasedEpochRandomGenerator UUIDV7_GENERATOR =
            Generators.timeBasedEpochRandomGenerator();

    private NotificationFactory() {
    }

    public static Notification createAnalyzerErrorNotification(final String content) {
        requireNonNull(content, "content must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_ANALYZER, LEVEL_ERROR)
                .setTitle("Analyzer Error")
                .setContent(content)
                .build();
    }

    public static Notification createBomConsumedNotification(
            final Project project,
            final Bom bom,
            final String token) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bom, "bom must not be null");
        requireNonNull(token, "token must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle("Bill of Materials Consumed")
                .setContent("A %s BOM was consumed and will be processed".formatted(bom.getFormat()))
                .setSubject(Any.pack(
                        BomConsumedOrProcessedSubject.newBuilder()
                                .setProject(project)
                                .setBom(bom)
                                .setToken(token)
                                .build()))
                .build();
    }

    public static Notification createBomConsumedNotification(
            final Project project,
            final @Nullable String bomFormat,
            final @Nullable String bomSpecVersion,
            final String token) {
        final var bomBuilder = Bom.newBuilder()
                .setContent("(Omitted)");
        if (bomFormat != null) {
            bomBuilder.setFormat(bomFormat);
        }
        if (bomSpecVersion != null) {
            bomBuilder.setSpecVersion(bomSpecVersion);
        }

        return createBomConsumedNotification(project, bomBuilder.build(), token);
    }

    public static Notification createBomProcessedNotification(
            final Project project,
            final Bom bom,
            final String token) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bom, "bom must not be null");
        requireNonNull(token, "token must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSED, LEVEL_INFORMATIONAL)
                .setTitle("Bill of Materials Processed")
                .setContent("A %s BOM was processed".formatted(bom.getFormat()))
                .setSubject(Any.pack(
                        BomConsumedOrProcessedSubject.newBuilder()
                                .setProject(project)
                                .setBom(bom)
                                .setToken(token)
                                .build()))
                .build();
    }

    public static Notification createBomProcessedNotification(
            final Project project,
            final @Nullable String bomFormat,
            final @Nullable String bomSpecVersion,
            final String token) {
        final var bomBuilder = Bom.newBuilder()
                .setContent("(Omitted)");
        if (bomFormat != null) {
            bomBuilder.setFormat(bomFormat);
        }
        if (bomSpecVersion != null) {
            bomBuilder.setSpecVersion(bomSpecVersion);
        }

        return createBomProcessedNotification(project, bomBuilder.build(), token);
    }

    public static Notification createBomProcessingFailedNotification(
            final Project project,
            final Bom bom,
            final String token,
            final String cause) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bom, "bom must not be null");
        requireNonNull(token, "token must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSING_FAILED, LEVEL_ERROR)
                .setTitle("Bill of Materials Processing Failed")
                .setContent("An error occurred while processing a BOM")
                .setSubject(Any.pack(
                        BomProcessingFailedSubject.newBuilder()
                                .setProject(project)
                                .setBom(bom)
                                .setCause(cause)
                                .setToken(token)
                                .build()))
                .build();
    }

    public static Notification createBomProcessingFailedNotification(
            final Project project,
            final @Nullable String bomFormat,
            final @Nullable String bomSpecVersion,
            final String token,
            final String cause) {
        final var bomBuilder = Bom.newBuilder()
                .setContent("(Omitted)");
        if (bomFormat != null) {
            bomBuilder.setFormat(bomFormat);
        }
        if (bomSpecVersion != null) {
            bomBuilder.setSpecVersion(bomSpecVersion);
        }

        return createBomProcessingFailedNotification(project, bomBuilder.build(), token, cause);
    }

    public static Notification createBomValidationFailedNotification(
            final Project project,
            final Collection<String> errors) {
        requireNonNull(project, "project must not be null");
        requireNonNull(errors, "errors must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_VALIDATION_FAILED, LEVEL_ERROR)
                .setTitle("Bill of Materials Validation Failed")
                .setContent("An error occurred while validating a BOM")
                .setSubject(Any.pack(
                        BomValidationFailedSubject.newBuilder()
                                .setProject(project)
                                .setBom(Bom.newBuilder()
                                        .setContent("(Omitted)")
                                        .build())
                                .addAllErrors(errors)
                                .build()))
                .build();
    }

    public static Notification createIntegrationErrorNotification(final String content) {
        requireNonNull(content, "content must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_INTEGRATION, LEVEL_ERROR)
                .setTitle("Integration Error")
                .setContent(content)
                .build();
    }

    public static Notification createNewVulnerabilityNotification(
            final Project project,
            final Component component,
            final Vulnerability vulnerability,
            final String vulnerabilityAnalysisLevel) {
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(vulnerability, "vulnerability must not be null");
        requireNonNull(vulnerabilityAnalysisLevel, "vulnerabilityAnalysisLevel must not be null");

        var title = "New Vulnerability Identified on Project: [" + project.getName();
        if (project.hasVersion()) {
            title += " : " + project.getVersion();
        }
        title += "]";

        final String content;
        if (vulnerability.hasDescription()) {
            content = vulnerability.getDescription();
        } else {
            content = vulnerability.hasTitle()
                    ? "%s: %s".formatted(vulnerability.getVulnId(), vulnerability.getTitle())
                    : vulnerability.getVulnId();
        }

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABILITY, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent(content)
                .setSubject(Any.pack(
                        NewVulnerabilitySubject.newBuilder()
                                .setProject(project)
                                .setComponent(component)
                                .setVulnerability(vulnerability)
                                .setVulnerabilityAnalysisLevel(vulnerabilityAnalysisLevel)
                                .setAffectedProjectsReference(
                                        BackReference.newBuilder()
                                                .setApiUri("/api/v1/vulnerability/source/%s/vuln/%s/projects".formatted(
                                                        vulnerability.getSource(), vulnerability.getVulnId()))
                                                .setFrontendUri("/vulnerabilities/%s/%s/affectedProjects".formatted(
                                                        vulnerability.getSource(), vulnerability.getVulnId()))
                                                .build())
                                .addAffectedProjects(project)
                                .build()))
                .build();
    }

    public static Notification createNewVulnerableDependencyNotification(
            final Project project,
            final Component component,
            final Collection<Vulnerability> vulnerabilities) {
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(vulnerabilities, "vulnerabilities must not be null");

        var title = "Vulnerable Dependency Introduced on Project: [" + project.getName();
        if (project.hasVersion()) {
            title += " : " + project.getVersion();
        }
        title += "]";

        final String content;
        if (vulnerabilities.size() == 1) {
            content = "A dependency was introduced that contains 1 known vulnerability";
        } else {
            content = """
                    A dependency was introduced that contains %s \
                    known vulnerabilities""".formatted(vulnerabilities.size());
        }

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_NEW_VULNERABLE_DEPENDENCY, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent(content)
                .setSubject(Any.pack(
                        NewVulnerableDependencySubject.newBuilder()
                                .setProject(project)
                                .setComponent(component)
                                .addAllVulnerabilities(vulnerabilities)
                                .build()))
                .build();
    }

    public static Notification createPolicyViolationAnalysisDecisionChangeNotification(
            final Project project,
            final Component component,
            final PolicyViolation violation,
            final PolicyViolationAnalysis analysis,
            final boolean analysisStateChanged,
            final boolean suppressionChanged) {
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(violation, "violation must not be null");
        requireNonNull(analysis, "analysis must not be null");

        var title = "Violation Analysis Decision: ";
        if (analysisStateChanged) {
            title += analysis.getState();
        } else if (suppressionChanged) {
            title += "Violation" + (analysis.getSuppressed() ? "Suppressed" : "Unsuppressed");
        } else {
            throw new IllegalArgumentException("""
                    Neither analysis state nor suppression have changed. \
                    The notification appears to have been created by mistake.""");
        }
        title += " on Project: [" + project.getName();
        if (project.hasVersion()) {
            title += " : " + project.getVersion();
        }
        title += "]";

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_AUDIT_CHANGE, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent("An violation analysis decision was made to a policy violation affecting a project")
                .setSubject(Any.pack(
                        PolicyViolationAnalysisDecisionChangeSubject.newBuilder()
                                .setProject(project)
                                .setComponent(component)
                                .setPolicyViolation(violation)
                                .setAnalysis(analysis)
                                .build()))
                .build();
    }

    public static Notification createPolicyViolationNotification(
            final Project project,
            final Component component,
            final PolicyViolation violation) {
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(violation, "violation must not be null");

        var title = "Policy Violation on Project: [" + project.getName();
        if (project.hasVersion()) {
            title += " : " + project.getVersion();
        }
        title += "]";

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_POLICY_VIOLATION, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent("A %s policy violation occurred".formatted(violation.getType().toLowerCase()))
                .setSubject(Any.pack(
                        PolicyViolationSubject.newBuilder()
                                .setProject(project)
                                .setComponent(component)
                                .setPolicyViolation(violation)
                                .build()))
                .build();
    }

    public static Notification createProjectCreatedNotification(final Project project) {
        requireNonNull(project, "project must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_CREATED, LEVEL_INFORMATIONAL)
                .setTitle("Project Added")
                .setContent(project.getName() + " was created")
                .setSubject(Any.pack(project))
                .build();
    }

    public static Notification createProjectVulnerabilityAnalysisCompleteNotification(
            final Project project,
            final Collection<ComponentVulnAnalysisCompleteSubject> findings,
            final ProjectVulnAnalysisStatus status,
            final String token) {
        requireNonNull(project, "project must not be null");
        requireNonNull(findings, "findings must not be null");
        requireNonNull(status, "status must not be null");
        requireNonNull(token, "token must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_VULN_ANALYSIS_COMPLETE, LEVEL_INFORMATIONAL)
                .setTitle("Project vulnerability analysis complete")
                .setContent("The vulnerability analysis of a project has completed")
                .setSubject(Any.pack(
                        ProjectVulnAnalysisCompleteSubject.newBuilder()
                                .setProject(project)
                                .addAllFindings(findings)
                                .setStatus(status)
                                .setToken(token)
                                .build()))
                .build();
    }

    public static Notification createUserCreatedNotification(final UserSubject user) {
        requireNonNull(user, "user must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_USER_CREATED, LEVEL_INFORMATIONAL)
                .setTitle("User Created")
                .setContent("User %s was created".formatted(user.getUsername()))
                .setSubject(Any.pack(user))
                .build();
    }

    public static Notification createUserDeletedNotification(final UserSubject user) {
        requireNonNull(user, "user must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_USER_DELETED, LEVEL_INFORMATIONAL)
                .setTitle("User Deleted")
                .setContent("User %s was deleted".formatted(user.getUsername()))
                .setSubject(Any.pack(user))
                .build();
    }

    public static Notification createVexConsumedNotification(
            final Project project,
            final Bom bom) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bom, "bom must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_VEX_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle("Vulnerability Exploitability Exchange (VEX) Consumed")
                .setContent("A %s VEX was consumed and will be processed".formatted(bom.getFormat()))
                .setSubject(Any.pack(
                        VexConsumedOrProcessedSubject.newBuilder()
                                .setProject(project)
                                .setFormat(bom.getFormat())
                                .setSpecVersion(bom.getSpecVersion())
                                .setVex(ByteString.copyFromUtf8(bom.getContent()))
                                .build()))
                .build();
    }

    public static Notification createVexProcessedNotification(
            final Project project,
            final Bom bom) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bom, "bom must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_VEX_PROCESSED, LEVEL_INFORMATIONAL)
                .setTitle("Vulnerability Exploitability Exchange (VEX) Processed")
                .setContent("A %s VEX was processed".formatted(bom.getFormat()))
                .setSubject(Any.pack(
                        VexConsumedOrProcessedSubject.newBuilder()
                                .setProject(project)
                                .setFormat(bom.getFormat())
                                .setSpecVersion(bom.getSpecVersion())
                                .setVex(ByteString.copyFromUtf8(bom.getContent()))
                                .build()))
                .build();
    }

    public static Notification createVulnerabilityAnalysisDecisionChangeNotification(
            final Project project,
            final Component component,
            final Vulnerability vulnerability,
            final VulnerabilityAnalysis analysis,
            final boolean analysisStateChanged,
            final boolean suppressionChanged) {
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(vulnerability, "vulnerability must not be null");
        requireNonNull(analysis, "analysis must not be null");

        final String title;
        if (analysisStateChanged) {
            title = "Analysis Decision: " + analysis.getState();
        } else if (suppressionChanged) {
            title = "Analysis Decision: Violation "
                    + (analysis.getSuppressed() ? "Suppressed" : "Unsuppressed");
        } else {
            throw new IllegalArgumentException("""
                    Neither analysis state nor suppression have changed. \
                    The notification appears to have been created by mistake.""");
        }

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_AUDIT_CHANGE, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent("An analysis decision was made to a finding affecting a project")
                .setSubject(Any.pack(
                        VulnerabilityAnalysisDecisionChangeSubject.newBuilder()
                                .setProject(project)
                                .setComponent(component)
                                .setVulnerability(vulnerability)
                                .setAnalysis(analysis)
                                .build()))
                .build();
    }

    static Notification.Builder newNotificationBuilder(
            final Scope scope,
            final Group group,
            final Level level) {
        requireNonNull(scope, "scope must not be null");
        requireNonNull(group, "group must not be null");
        requireNonNull(level, "level must not be null");

        if (scope == SCOPE_UNSPECIFIED || scope == Scope.UNRECOGNIZED) {
            throw new IllegalArgumentException("Invalid scope: " + scope);
        }
        if (group == GROUP_UNSPECIFIED || group == Group.UNRECOGNIZED) {
            throw new IllegalArgumentException("Invalid group: " + group);
        }
        if (level == LEVEL_UNSPECIFIED || level == Level.UNRECOGNIZED) {
            throw new IllegalArgumentException("Invalid level: " + level);
        }

        final long nowMillis = System.currentTimeMillis();

        return Notification.newBuilder()
                .setId(UUIDV7_GENERATOR.construct(nowMillis).toString())
                .setTimestamp(Timestamps.fromMillis(nowMillis))
                .setScope(scope)
                .setGroup(group)
                .setLevel(level);
    }

}
