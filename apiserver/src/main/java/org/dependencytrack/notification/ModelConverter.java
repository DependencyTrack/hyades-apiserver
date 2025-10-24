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

import alpine.model.User;
import alpine.notification.NotificationLevel;
import org.dependencytrack.model.Tag;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Scope;
import org.dependencytrack.proto.notification.v1.UserSubject;

/**
 * TODO: Merge with {@link org.dependencytrack.parser.dependencytrack.NotificationModelConverter}.
 *
 * @since 5.7.0
 */
final class ModelConverter {

    private ModelConverter() {
    }

    static NotificationGroup convert(final Group protoGroup) {
        return switch (protoGroup) {
            case GROUP_ANALYZER -> NotificationGroup.ANALYZER;
            case GROUP_BOM_CONSUMED -> NotificationGroup.BOM_CONSUMED;
            case GROUP_BOM_PROCESSED -> NotificationGroup.BOM_PROCESSED;
            case GROUP_BOM_PROCESSING_FAILED -> NotificationGroup.BOM_PROCESSING_FAILED;
            case GROUP_BOM_VALIDATION_FAILED -> NotificationGroup.BOM_VALIDATION_FAILED;
            case GROUP_CONFIGURATION -> NotificationGroup.CONFIGURATION;
            case GROUP_DATASOURCE_MIRRORING -> NotificationGroup.DATASOURCE_MIRRORING;
            case GROUP_FILE_SYSTEM -> NotificationGroup.FILE_SYSTEM;
            case GROUP_INTEGRATION -> NotificationGroup.INTEGRATION;
            case GROUP_NEW_VULNERABILITY -> NotificationGroup.NEW_VULNERABILITY;
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> NotificationGroup.NEW_VULNERABLE_DEPENDENCY;
            case GROUP_POLICY_VIOLATION -> NotificationGroup.POLICY_VIOLATION;
            case GROUP_PROJECT_AUDIT_CHANGE -> NotificationGroup.PROJECT_AUDIT_CHANGE;
            case GROUP_PROJECT_CREATED -> NotificationGroup.PROJECT_CREATED;
            case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> NotificationGroup.PROJECT_VULN_ANALYSIS_COMPLETE;
            case GROUP_REPOSITORY -> NotificationGroup.REPOSITORY;
            case GROUP_USER_CREATED -> NotificationGroup.USER_CREATED;
            case GROUP_USER_DELETED -> NotificationGroup.USER_DELETED;
            case GROUP_VEX_CONSUMED -> NotificationGroup.VEX_CONSUMED;
            case GROUP_VEX_PROCESSED -> NotificationGroup.VEX_PROCESSED;
            case GROUP_UNSPECIFIED, UNRECOGNIZED -> throw new IllegalArgumentException("Unknown group: " + protoGroup);
        };
    }

    static NotificationLevel convert(final Level protoLevel) {
        return switch (protoLevel) {
            case LEVEL_ERROR -> NotificationLevel.ERROR;
            case LEVEL_INFORMATIONAL -> NotificationLevel.INFORMATIONAL;
            case LEVEL_WARNING -> NotificationLevel.WARNING;
            case LEVEL_UNSPECIFIED, UNRECOGNIZED -> throw new IllegalArgumentException("Unknown level: " + protoLevel);
        };
    }

    static NotificationScope convert(final Scope protoScope) {
        return switch (protoScope) {
            case SCOPE_PORTFOLIO -> NotificationScope.PORTFOLIO;
            case SCOPE_SYSTEM -> NotificationScope.SYSTEM;
            case SCOPE_UNSPECIFIED, UNRECOGNIZED -> throw new IllegalArgumentException("Unknown scope: " + protoScope);
        };
    }

    static Project convert(final org.dependencytrack.model.Project project) {
        final Project.Builder builder = Project.newBuilder()
                .setUuid(project.getUuid().toString())
                .setName(project.getName())
                .setIsActive(project.isActive());

        if (project.getVersion() != null) {
            builder.setVersion(project.getVersion());
        }
        if (project.getDescription() != null) {
            builder.setDescription(project.getDescription());
        }
        if (project.getPurl() != null) {
            builder.setPurl(project.getPurl().canonicalize());
        }
        if (project.getTags() != null) {
            for (final Tag tag : project.getTags()) {
                builder.addTags(tag.getName());
            }
        }

        return builder.build();
    }

    static UserSubject convert(final User user) {
        final var builder = UserSubject.newBuilder()
                .setUsername(user.getUsername());
        if (user.getEmail() != null) {
            builder.setEmail(user.getEmail());
        }
        return builder.build();
    }

}
