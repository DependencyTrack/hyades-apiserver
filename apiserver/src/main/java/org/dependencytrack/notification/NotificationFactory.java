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
import org.dependencytrack.proto.notification.v1.Notification;
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
import static org.dependencytrack.proto.notification.v1.Group.GROUP_PROJECT_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_USER_CREATED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_USER_DELETED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_VEX_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_SYSTEM;

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

        return newNotificationBuilder()
                .setLevel(LEVEL_ERROR)
                .setScope(SCOPE_SYSTEM)
                .setGroup(GROUP_ANALYZER)
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

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_BOM_CONSUMED)
                .setTitle("Bill of Materials Consumed")
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

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_BOM_PROCESSED)
                .setTitle("Bill of Materials Processed")
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

        return newNotificationBuilder()
                .setLevel(LEVEL_ERROR)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_BOM_PROCESSING_FAILED)
                .setTitle("Bill of Materials Processing Failed")
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

        return newNotificationBuilder()
                .setLevel(LEVEL_ERROR)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_BOM_VALIDATION_FAILED)
                .setTitle("Bill of Materials Validation Failed")
                .setContent("An error occurred while validating a BOM")
                .setSubject(Any.pack(subjectBuilder.build()))
                .build();
    }

    public static Notification createIntegrationErrorNotification(final String content) {
        requireNonNull(content, "content must not be null");

        return newNotificationBuilder()
                .setLevel(LEVEL_ERROR)
                .setScope(SCOPE_SYSTEM)
                .setGroup(GROUP_INTEGRATION)
                .setTitle("Integration Error")
                .setContent(content)
                .build();
    }

    public static Notification createProjectCreatedNotification(
            final org.dependencytrack.model.Project project) {
        requireNonNull(project, "project must not be null");

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_PROJECT_CREATED)
                .setTitle("Project Added")
                .setContent(project.getName() + " was created")
                .setSubject(Any.pack(convert(project)))
                .build();
    }

    public static Notification createUserCreatedNotification(
            final alpine.model.User user) {
        requireNonNull(user, "user must not be null");

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_SYSTEM)
                .setGroup(GROUP_USER_CREATED)
                .setTitle("User Created")
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

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_SYSTEM)
                .setGroup(GROUP_USER_DELETED)
                .setTitle("User Deleted")
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

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_VEX_CONSUMED)
                .setTitle("Vulnerability Exploitability Exchange (VEX) Consumed")
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

        return newNotificationBuilder()
                .setLevel(LEVEL_INFORMATIONAL)
                .setScope(SCOPE_PORTFOLIO)
                .setGroup(GROUP_VEX_PROCESSED)
                .setTitle("Vulnerability Exploitability Exchange (VEX) Processed")
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

    public static Notification.Builder newNotificationBuilder() {
        final long nowMillis = System.currentTimeMillis();

        return Notification.newBuilder()
                .setId(UUIDV7_GENERATOR.construct(nowMillis).toString())
                .setTimestamp(Timestamps.fromMillis(nowMillis));
    }

}
