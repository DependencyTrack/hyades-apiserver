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
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Tag;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Policy;
import org.dependencytrack.proto.notification.v1.PolicyCondition;
import org.dependencytrack.proto.notification.v1.PolicyViolation;
import org.dependencytrack.proto.notification.v1.PolicyViolationAnalysis;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Scope;
import org.dependencytrack.proto.notification.v1.UserSubject;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysis;

import java.util.Objects;

import static org.dependencytrack.util.VulnerabilityUtil.getUniqueAliases;

/**
 * @since 5.7.0
 */
public final class ModelConverter {

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

    public static Component convert(final org.dependencytrack.model.Component component) {
        final Component.Builder builder = Component.newBuilder()
                .setUuid(component.getUuid().toString())
                .setName(component.getName());
        if (component.getGroup() != null) {
            builder.setGroup(component.getGroup());
        }
        if (component.getVersion() != null) {
            builder.setVersion(component.getVersion());
        }
        if (component.getPurl() != null) {
            builder.setPurl(component.getPurl().canonicalize());
        }
        if (component.getMd5() != null) {
            builder.setMd5(component.getMd5());
        }
        if (component.getSha1() != null) {
            builder.setSha1(component.getSha1());
        }
        if (component.getSha256() != null) {
            builder.setSha256(component.getSha256());
        }
        if (component.getSha512() != null) {
            builder.setSha512(component.getSha512());
        }
        return builder.build();
    }

    public static Policy convert(final org.dependencytrack.model.Policy policy) {
        return Policy.newBuilder()
                .setUuid(policy.getUuid().toString())
                .setName(policy.getName())
                .setViolationState(policy.getViolationState().name())
                .build();
    }

    public static PolicyCondition convert(final org.dependencytrack.model.PolicyCondition condition) {
        return PolicyCondition.newBuilder()
                .setUuid(condition.getUuid().toString())
                .setPolicy(convert(condition.getPolicy()))
                .setSubject(condition.getSubject().name())
                .setOperator(condition.getOperator().name())
                .setValue(condition.getValue())
                .build();
    }

    public static PolicyViolation convert(final org.dependencytrack.model.PolicyViolation violation) {
        return PolicyViolation.newBuilder()
                .setUuid(violation.getUuid().toString())
                .setCondition(convert(violation.getPolicyCondition()))
                .setType(violation.getType().name())
                .setTimestamp(Timestamps.fromDate(violation.getTimestamp()))
                .build();
    }

    public static PolicyViolationAnalysis convert(final org.dependencytrack.model.ViolationAnalysis analysis) {
        return PolicyViolationAnalysis.newBuilder()
                .setProject(convert(analysis.getProject()))
                .setComponent(convert(analysis.getComponent()))
                .setPolicyViolation(convert(analysis.getPolicyViolation()))
                .setState(analysis.getAnalysisState().name())
                .setSuppressed(analysis.isSuppressed())
                .build();
    }

    public static Project convert(final org.dependencytrack.model.Project project) {
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

    public static Vulnerability convert(final org.dependencytrack.model.Vulnerability vuln) {
        final Vulnerability.Builder builder = Vulnerability.newBuilder()
                .setUuid(vuln.getUuid().toString())
                .setVulnId(vuln.getVulnId())
                .setSource(vuln.getSource());

        if (vuln.getAliases() != null) {
            getUniqueAliases(vuln).stream()
                    .map(entry -> Vulnerability.Alias.newBuilder()
                            .setId(entry.getValue())
                            .setSource(entry.getKey().name()))
                    .forEach(builder::addAliases);
        }
        if (vuln.getTitle() != null) {
            builder.setTitle(vuln.getTitle());
        }
        if (vuln.getSubTitle() != null) {
            builder.setSubTitle(vuln.getSubTitle());
        }
        if (vuln.getDescription() != null) {
            builder.setDescription(vuln.getDescription());
        }
        if (vuln.getRecommendation() != null) {
            builder.setRecommendation(vuln.getRecommendation());
        }
        if (vuln.getCvssV2BaseScore() != null) {
            builder.setCvssV2(vuln.getCvssV2BaseScore().doubleValue());
        }
        if (vuln.getCvssV3BaseScore() != null) {
            builder.setCvssV3(vuln.getCvssV3BaseScore().doubleValue());
        }
        if (vuln.getCvssV2Vector() != null) {
            builder.setCvssV2Vector(vuln.getCvssV2Vector());
        }
        if (vuln.getCvssV3Vector() != null) {
            builder.setCvssV3Vector(vuln.getCvssV3Vector());
        }
        if (vuln.getOwaspRRLikelihoodScore() != null) {
            builder.setOwaspRrLikelihood(vuln.getOwaspRRLikelihoodScore().doubleValue());
        }
        if (vuln.getOwaspRRTechnicalImpactScore() != null) {
            builder.setOwaspRrTechnicalImpact(vuln.getOwaspRRTechnicalImpactScore().doubleValue());
        }
        if (vuln.getOwaspRRBusinessImpactScore() != null) {
            builder.setOwaspRrBusinessImpact(vuln.getOwaspRRBusinessImpactScore().doubleValue());
        }
        if (vuln.getOwaspRRVector() != null) {
            builder.setOwaspRrVector(vuln.getOwaspRRVector());
        }
        if (vuln.getSeverity() != null) {
            builder.setSeverity(vuln.getSeverity().name());
        }
        if (vuln.getCwes() != null && !vuln.getCwes().isEmpty()) {
            vuln.getCwes().stream()
                    .map(cweId -> {
                        final Cwe cwe = CweResolver.getInstance().lookup(cweId);
                        if (cwe == null) {
                            return null;
                        }

                        return Vulnerability.Cwe.newBuilder()
                                .setCweId(cweId)
                                .setName(cwe.getName())
                                .build();
                    })
                    .filter(Objects::nonNull)
                    .forEach(builder::addCwes);
        }

        return builder.build();
    }

    static VulnerabilityAnalysis convert(final org.dependencytrack.model.Analysis analysis) {
        return VulnerabilityAnalysis.newBuilder()
                .setProject(convert(analysis.getProject()))
                .setComponent(convert(analysis.getComponent()))
                .setVulnerability(convert(analysis.getVulnerability()))
                .setState(analysis.getAnalysisState().name())
                .setSuppressed(analysis.isSuppressed())
                .build();
    }

}
