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
package org.dependencytrack.notification.publishing.testing;

import com.google.protobuf.Any;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.notification.v1.BackReference;
import org.dependencytrack.proto.notification.v1.Bom;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Vulnerability;

import java.util.List;

import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_DATASOURCE_MIRRORING;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_SYSTEM;

/**
 * @since 5.7.0
 */
public final class NotificationFixtures {

    public static final Notification BOM_CONSUMED_NOTIFICATION =
            Notification.newBuilder()
                    .setScope(SCOPE_PORTFOLIO)
                    .setGroup(GROUP_BOM_CONSUMED)
                    .setTitle("Bill of Materials Consumed")
                    .setContent("A CycloneDX BOM was consumed and will be processed")
                    .setLevel(LEVEL_INFORMATIONAL)
                    .setTimestamp(Timestamps.fromSeconds(66666))
                    .setSubject(Any.pack(
                            BomConsumedOrProcessedSubject.newBuilder()
                                    .setProject(createProject())
                                    .setBom(Bom.newBuilder()
                                            .setContent("bomContent")
                                            .setFormat("CycloneDX")
                                            .setSpecVersion("1.5"))
                                    .build()))
                    .build();

    public static final Notification BOM_PROCESSING_FAILED_NOTIFICATION =
            Notification.newBuilder()
                    .setScope(SCOPE_PORTFOLIO)
                    .setGroup(GROUP_BOM_PROCESSING_FAILED)
                    .setTitle("Bill of Materials Processing Failed")
                    .setContent("An error occurred while processing a BOM")
                    .setLevel(LEVEL_ERROR)
                    .setTimestamp(Timestamps.fromSeconds(66666))
                    .setSubject(Any.pack(
                            BomProcessingFailedSubject.newBuilder()
                                    .setProject(createProject())
                                    .setBom(Bom.newBuilder()
                                            .setContent("bomContent")
                                            .setFormat("CycloneDX")
                                            .setSpecVersion("1.5"))
                                    .setCause("cause")
                                    .build()))
                    .build();

    public static final Notification BOM_VALIDATION_FAILED_NOTIFICATION =
            Notification.newBuilder()
                    .setScope(SCOPE_PORTFOLIO)
                    .setGroup(GROUP_BOM_VALIDATION_FAILED)
                    .setTitle("Bill of Materials Validation Failed")
                    .setContent("An error occurred while validating a BOM")
                    .setLevel(LEVEL_ERROR)
                    .setTimestamp(Timestamps.fromSeconds(66666))
                    .setSubject(Any.pack(
                            BomValidationFailedSubject.newBuilder()
                                    .setProject(createProject())
                                    .setBom(Bom.newBuilder()
                                            .setContent("bomContent")
                                            .setFormat("CycloneDX"))
                                    .addErrors("cause 1")
                                    .addErrors("cause 2")
                                    .build()))
                    .build();

    public static final Notification DATA_SOURCE_MIRRORING_NOTIFICATION =
            Notification.newBuilder()
                    .setScope(SCOPE_SYSTEM)
                    .setGroup(GROUP_DATASOURCE_MIRRORING)
                    .setTitle("GitHub Advisory Mirroring")
                    .setContent("An error occurred mirroring the contents of GitHub Advisories. Check log for details.")
                    .setLevel(LEVEL_ERROR)
                    .setTimestamp(Timestamps.fromSeconds(66666))
                    .build();

    public static final Notification NEW_VULNERABILITY_NOTIFICATION =
            Notification.newBuilder()
                    .setScope(SCOPE_PORTFOLIO)
                    .setGroup(GROUP_NEW_VULNERABILITY)
                    .setTitle("New Vulnerability Identified")
                    .setContent("")
                    .setLevel(LEVEL_INFORMATIONAL)
                    .setTimestamp(Timestamps.fromSeconds(66666))
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

    public static final Notification NEW_VULNERABLE_DEPENDENCY_NOTIFICATION =
            Notification.newBuilder()
                    .setScope(SCOPE_PORTFOLIO)
                    .setGroup(GROUP_NEW_VULNERABLE_DEPENDENCY)
                    .setTitle("Vulnerable Dependency Introduced")
                    .setContent("")
                    .setLevel(LEVEL_INFORMATIONAL)
                    .setTimestamp(Timestamps.fromSeconds(66666))
                    .setSubject(Any.pack(
                            NewVulnerableDependencySubject.newBuilder()
                                    .setComponent(createComponent())
                                    .setProject(createProject())
                                    .addVulnerabilities(createVulnerability())
                                    .build()))
                    .build();

    private NotificationFixtures() {
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

    private static Component createComponent() {
        return Component.newBuilder()
                .setUuid("94f87321-a5d1-4c2f-b2fe-95165debebc6")
                .setName("componentName")
                .setVersion("componentVersion")
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

}
