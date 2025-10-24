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

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochRandomGenerator;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.notification.v1.Bom;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Scope;
import org.dependencytrack.proto.notification.v1.VexConsumedOrProcessedSubject;

import java.util.Collection;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_ANALYZER;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_INTEGRATION;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_POLICY_VIOLATION;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_UNSPECIFIED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_USER_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_USER_DELETED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_UNSPECIFIED;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_SYSTEM;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_UNSPECIFIED;

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

    // TODO: Add methods for remaining notifications.

    public static Notification createAnalyzerErrorNotification(final String content) {
        requireNonNull(content, "content must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_ANALYZER, LEVEL_ERROR)
                .setTitle("Analyzer Error")
                .setContent(content)
                .build();
    }

    public static Notification createBomConsumedNotification(
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Bom.Format bomFormat,
            final String bomSpecVersion,
            final UUID uploadToken) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bomFormat, "bomFormat must not be null");
        requireNonNull(bomSpecVersion, "bomSpecVersion must not be null");
        requireNonNull(uploadToken, "uploadToken must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.BOM_CONSUMED)
                .setContent("A %s BOM was consumed and will be processed".formatted(bomFormat.getFormatShortName()))
                .setSubject(Any.pack(
                        BomConsumedOrProcessedSubject.newBuilder()
                                .setProject(convert(project))
                                .setBom(Bom.newBuilder()
                                        .setFormat(bomFormat.getFormatShortName())
                                        .setSpecVersion(bomSpecVersion)
                                        .setContent("(Omitted)")
                                        .build())
                                .setToken(uploadToken.toString())
                                .build()))
                .build();
    }

    public static Notification createBomProcessedNotification(
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Bom.Format bomFormat,
            final String bomSpecVersion,
            final UUID uploadToken) {
        requireNonNull(project, "project must not be null");
        requireNonNull(bomFormat, "bomFormat must not be null");
        requireNonNull(bomSpecVersion, "bomSpecVersion must not be null");
        requireNonNull(uploadToken, "uploadToken must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.BOM_PROCESSED)
                .setContent("A %s BOM was processed".formatted(bomFormat.getFormatShortName()))
                .setSubject(Any.pack(
                        BomConsumedOrProcessedSubject.newBuilder()
                                .setProject(convert(project))
                                .setBom(Bom.newBuilder()
                                        .setFormat(bomFormat.getFormatShortName())
                                        .setSpecVersion(bomSpecVersion)
                                        .setContent("(Omitted)")
                                        .build())
                                .setToken(uploadToken.toString())
                                .build()))
                .build();
    }

    public static Notification createBomProcessingFailedNotification(
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Bom.Format bomFormat,
            final String bomSpecVersion,
            final Throwable cause,
            final UUID uploadToken) {
        requireNonNull(project, "project must not be null");
        requireNonNull(cause, "cause must not be null");
        requireNonNull(uploadToken, "uploadToken must not be null");

        final var bomBuilder = Bom.newBuilder()
                .setContent("(Omitted)");

        // Format and specVersion may be null of processing failed
        // before the BOM could be parsed.
        if (bomFormat != null) {
            bomBuilder.setFormat(bomFormat.getFormatShortName());
        }
        if (bomSpecVersion != null) {
            bomBuilder.setSpecVersion(bomSpecVersion);
        }

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_PROCESSING_FAILED, LEVEL_ERROR)
                .setTitle(NotificationConstants.Title.BOM_PROCESSING_FAILED)
                .setContent("An error occurred while processing a BOM")
                .setSubject(Any.pack(
                        BomProcessingFailedSubject.newBuilder()
                                .setProject(convert(project))
                                .setBom(bomBuilder.build())
                                .setCause(cause.getMessage())
                                .setToken(uploadToken.toString())
                                .build()))
                .build();
    }

    public static Notification createBomValidationFailedNotification(
            final org.dependencytrack.model.Project project,
            final Collection<String> errors) {
        requireNonNull(project, "project must not be null");

        final var subjectBuilder = BomValidationFailedSubject.newBuilder()
                .setProject(convert(project))
                .setBom(Bom.newBuilder()
                        .setContent("(Omitted)")
                        .build());

        // If validation failed for reasons other than
        // schema conformance, errors may be null.
        if (errors != null && !errors.isEmpty()) {
            subjectBuilder.addAllErrors(errors);
        }

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_BOM_VALIDATION_FAILED, LEVEL_ERROR)
                .setTitle(NotificationConstants.Title.BOM_VALIDATION_FAILED)
                .setContent("An error occurred while validating a BOM")
                .setSubject(Any.pack(subjectBuilder.build()))
                .build();
    }

    public static Notification createIntegrationErrorNotification(final String content) {
        requireNonNull(content, "content must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_INTEGRATION, LEVEL_ERROR)
                .setTitle(NotificationConstants.Title.INTEGRATION_ERROR)
                .setContent(content)
                .build();
    }

    public static Notification createPolicyViolationAnalysisDecisionChangeNotification(
            final String title,
            final String content,
            final org.dependencytrack.model.Component component,
            final org.dependencytrack.model.PolicyViolation policyViolation,
            final org.dependencytrack.model.ViolationAnalysis violationAnalysis) {
        requireNonNull(title, "title must not be null");
        requireNonNull(content, "content must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(policyViolation, "policyViolation must not be null");
        requireNonNull(violationAnalysis, "violationAnalysis must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_AUDIT_CHANGE, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent(content)
                .build();
    }

    public static Notification createPolicyViolationNotification(
            final String title,
            final String content,
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Component component,
            final org.dependencytrack.model.PolicyViolation violation) {
        requireNonNull(title, "title must not be null");
        requireNonNull(content, "content must not be null");
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(violation, "violation must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_POLICY_VIOLATION, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent(content)
                .build();
    }

    public static Notification createProjectCreatedNotification(
            final org.dependencytrack.model.Project project) {
        requireNonNull(project, "project must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_CREATED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.PROJECT_CREATED)
                .setContent(project.getName() + " was created")
                .setSubject(Any.pack(convert(project)))
                .build();
    }

    public static Notification createUserCreatedNotification(
            final alpine.model.User user) {
        requireNonNull(user, "user must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_USER_CREATED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.USER_CREATED)
                .setContent(switch (user) {
                    case LdapUser ignored -> "LDAP";
                    case ManagedUser ignored -> "Managed";
                    case OidcUser ignored -> "OpenID Connect";
                    default -> throw new IllegalStateException(
                            "Unexpected user type: " + user.getClass());
                } + " user created")
                .setSubject(Any.pack(convert(user)))
                .build();
    }

    public static Notification createUserDeletedNotification(
            final alpine.model.User user) {
        requireNonNull(user, "user must not be null");

        return newNotificationBuilder(SCOPE_SYSTEM, GROUP_USER_DELETED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.USER_DELETED)
                .setContent(switch (user) {
                    case LdapUser ignored -> "LDAP";
                    case ManagedUser ignored -> "Managed";
                    case OidcUser ignored -> "OpenID Connect";
                    default -> throw new IllegalStateException(
                            "Unexpected user type: " + user.getClass());
                } + " user deleted")
                .setSubject(Any.pack(convert(user)))
                .build();
    }

    public static Notification createVexConsumedNotification(
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Vex.Format vexFormat,
            final String vexSpecVersion) {
        requireNonNull(project, "project must not be null");
        requireNonNull(vexFormat, "vexFormat must not be null");
        requireNonNull(vexSpecVersion, "vexSpecVersion must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_VEX_CONSUMED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.VEX_CONSUMED)
                .setContent("A %s VEX was consumed and will be processed".formatted(vexFormat.getFormatShortName()))
                .setSubject(Any.pack(
                        VexConsumedOrProcessedSubject.newBuilder()
                                .setProject(convert(project))
                                .setFormat(vexFormat.getFormatShortName())
                                .setSpecVersion(vexSpecVersion)
                                .setVex(ByteString.copyFromUtf8("(Omitted)"))
                                .build()))
                .build();
    }

    public static Notification createVexProcessedNotification(
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Vex.Format vexFormat,
            final String vexSpecVersion) {
        requireNonNull(project, "project must not be null");
        requireNonNull(vexFormat, "vexFormat must not be null");
        requireNonNull(vexSpecVersion, "vexSpecVersion must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_VEX_PROCESSED, LEVEL_INFORMATIONAL)
                .setTitle(NotificationConstants.Title.VEX_PROCESSED)
                .setContent("A %s VEX was processed".formatted(vexFormat.getFormatShortName()))
                .setSubject(Any.pack(
                        VexConsumedOrProcessedSubject.newBuilder()
                                .setProject(convert(project))
                                .setFormat(vexFormat.getFormatShortName())
                                .setSpecVersion(vexSpecVersion)
                                .setVex(ByteString.copyFromUtf8("(Omitted)"))
                                .build()))
                .build();
    }

    public static Notification createVulnerabilityAnalysisDecisionChangeNotification(
            final String title,
            final String content,
            final org.dependencytrack.model.Project project,
            final org.dependencytrack.model.Component component,
            final org.dependencytrack.model.Vulnerability vulnerability,
            final org.dependencytrack.model.Analysis analysis) {
        requireNonNull(title, "title must not be null");
        requireNonNull(content, "content must not be null");
        requireNonNull(project, "project must not be null");
        requireNonNull(component, "component must not be null");
        requireNonNull(vulnerability, "vulnerability must not be null");
        requireNonNull(analysis, "analysis must not be null");

        return newNotificationBuilder(SCOPE_PORTFOLIO, GROUP_PROJECT_AUDIT_CHANGE, LEVEL_INFORMATIONAL)
                .setTitle(title)
                .setContent(content)
                .build();
    }

    public static Notification.Builder newNotificationBuilder(
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
