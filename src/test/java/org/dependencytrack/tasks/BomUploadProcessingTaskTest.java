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
package org.dependencytrack.tasks;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowStep;
import org.hyades.proto.notification.v1.BomProcessingFailedSubject;
import org.hyades.proto.notification.v1.Group;
import org.hyades.proto.notification.v1.Notification;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.dependencytrack.model.WorkflowStatus.CANCELLED;
import static org.dependencytrack.model.WorkflowStatus.COMPLETED;
import static org.dependencytrack.model.WorkflowStatus.FAILED;
import static org.dependencytrack.model.WorkflowStatus.NOT_APPLICABLE;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.model.WorkflowStep.BOM_CONSUMPTION;
import static org.dependencytrack.model.WorkflowStep.BOM_PROCESSING;
import static org.dependencytrack.model.WorkflowStep.METRICS_UPDATE;
import static org.dependencytrack.model.WorkflowStep.POLICY_EVALUATION;
import static org.dependencytrack.model.WorkflowStep.VULN_ANALYSIS;
import static org.dependencytrack.util.KafkaTestUtil.deserializeKey;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;
import static org.hyades.proto.notification.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.hyades.proto.notification.v1.Level.LEVEL_ERROR;
import static org.hyades.proto.notification.v1.Scope.SCOPE_PORTFOLIO;

public class BomUploadProcessingTaskTest extends AbstractPostgresEnabledTest {

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());
    }

    @Test
    public void informTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-1.xml"));
        qm.createWorkflowSteps(bomUploadEvent.getChainIdentifier());

        new BomUploadProcessingTask().inform(bomUploadEvent);
        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() >= 5, Duration.ofSeconds(5));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name()),
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.VULN_ANALYSIS_COMMAND.name()),
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name()),
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name())
        );
        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getLastBomImport()).isNotNull();
        assertThat(project.getExternalReferences()).isNotNull();
        assertThat(project.getExternalReferences()).hasSize(4);

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(1);

        final Component component = components.get(0);
        assertThat(component.getAuthor()).isEqualTo("Sometimes this field is long because it is composed of a list of authors......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................");
        assertThat(component.getPublisher()).isEqualTo("Example Incorporated");
        assertThat(component.getGroup()).isEqualTo("com.example");
        assertThat(component.getName()).isEqualTo("xmlutil");
        assertThat(component.getVersion()).isEqualTo("1.0.0");
        assertThat(component.getDescription()).isEqualTo("A makebelieve XML utility library");
        assertThat(component.getCpe()).isEqualTo("cpe:/a:example:xmlutil:1.0.0");
        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:maven/com.example/xmlutil@1.0.0?download_url=https%3A%2F%2Fon-premises.url%2Frepository%2Fnpm%2F%40babel%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration%2Fhelper-split-export-declaration-7.18.6.tgz");
        assertThat(component.getLicenseUrl()).isEqualTo("https://www.apache.org/licenses/LICENSE-2.0.txt");

        assertThat(qm.getAllWorkflowStatesForAToken(bomUploadEvent.getChainIdentifier())).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_PROCESSING);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    //vuln analysis has not been handled yet, so it will be in pending state
                    assertThat(state.getStep()).isEqualTo(VULN_ANALYSIS);
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getStartedAt()).isBefore(Date.from(Instant.now()));
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    //policy evaluation has not been handled yet, so it will be in pending state
                    assertThat(state.getStep()).isEqualTo(POLICY_EVALUATION);
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    //metrics update has not been handled yet, so it will be in pending state
                    assertThat(state.getStep()).isEqualTo(METRICS_UPDATE);
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                }
        );
        final VulnerabilityScan vulnerabilityScan = qm.getVulnerabilityScan(bomUploadEvent.getChainIdentifier().toString());
        assertThat(vulnerabilityScan).isNotNull();
        var workflowStatus = qm.getWorkflowStateByTokenAndStep(bomUploadEvent.getChainIdentifier(), WorkflowStep.VULN_ANALYSIS);
        assertThat(workflowStatus.getStartedAt()).isNotNull();
    }

    @Test
    public void informWithEmptyBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-empty.json"));
        qm.createWorkflowSteps(bomUploadEvent.getChainIdentifier());
        new BomUploadProcessingTask().inform(bomUploadEvent);
        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() >= 3, Duration.ofSeconds(5));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name()),
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name())
        );

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNotNull();

        assertThat(qm.getAllWorkflowStatesForAToken(bomUploadEvent.getChainIdentifier())).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_PROCESSING);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(VULN_ANALYSIS);
                    assertThat(state.getStatus()).isEqualTo(NOT_APPLICABLE);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(POLICY_EVALUATION);
                    assertThat(state.getStatus()).isEqualTo(NOT_APPLICABLE);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(METRICS_UPDATE);
                    assertThat(state.getStatus()).isEqualTo(PENDING);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                }
        );

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();
        final VulnerabilityScan vulnerabilityScan = qm.getVulnerabilityScan(bomUploadEvent.getChainIdentifier().toString());
        assertThat(vulnerabilityScan).isNull();
    }

    @Test
    public void informWithInvalidBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-invalid.json"));
        qm.createWorkflowSteps(bomUploadEvent.getChainIdentifier());
        new BomUploadProcessingTask().inform(bomUploadEvent);
        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() >= 2, Duration.ofSeconds(5));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                event -> {
                    assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                    final Notification notification = deserializeValue(KafkaTopics.NOTIFICATION_BOM, event);
                    assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
                    assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
                    assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
                    assertThat(notification.getTitle()).isNotEmpty();
                    assertThat(notification.getContent()).isNotEmpty();
                    assertThat(notification.hasSubject()).isTrue();
                    assertThat(notification.getSubject().is(BomProcessingFailedSubject.class)).isTrue();
                    final var subject = notification.getSubject().unpack(BomProcessingFailedSubject.class);
                    assertThat(subject.hasProject()).isTrue();
                    assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
                    assertThat(subject.getBom().getContent()).isEqualTo("(Omitted)");
                    assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
                    assertThat(subject.getBom().getSpecVersion()).isEmpty();
                }
        );

        qm.getPersistenceManager().refresh(project);

        assertThat(qm.getAllWorkflowStatesForAToken(bomUploadEvent.getChainIdentifier())).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getStatus()).isEqualTo(FAILED);
                    assertThat(state.getFailureReason()).isEqualTo("Failed to parse BOM");
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_PROCESSING);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(VULN_ANALYSIS);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(POLICY_EVALUATION);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(METRICS_UPDATE);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                }
        );
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNull();
        assertThat(project.getExternalReferences()).isNull();
        assertThat(project.getExternalReferences()).isNull();

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();
    }

    @Test
    public void testBomProcessingShouldFailIfProjectDoesNotExists() throws Exception {
        //project should not be persisted for this test condition
        Project project = new Project();
        project.setUuid(UUID.randomUUID());
        project.setName("test-project");
        project.setId(1);
        var bomUploadEvent = new BomUploadEvent(project, createTempBomFile("bom-1.xml"));
        qm.createWorkflowSteps(bomUploadEvent.getChainIdentifier());
        new BomUploadProcessingTask().inform(bomUploadEvent);

        assertThat(qm.getAllWorkflowStatesForAToken(bomUploadEvent.getChainIdentifier())).satisfiesExactlyInAnyOrder(
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_CONSUMPTION);
                    assertThat(state.getStatus()).isEqualTo(COMPLETED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(BOM_PROCESSING);
                    assertThat(state.getStatus()).isEqualTo(FAILED);
                    assertThat(state.getStartedAt()).isNotNull();
                    assertThat(state.getFailureReason()).isEqualTo("Project does not exist");
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(VULN_ANALYSIS);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(POLICY_EVALUATION);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                },
                state -> {
                    assertThat(state.getStep()).isEqualTo(METRICS_UPDATE);
                    assertThat(state.getStatus()).isEqualTo(CANCELLED);
                    assertThat(state.getParent()).isNotNull();
                    assertThat(state.getStartedAt()).isNull();
                    assertThat(state.getUpdatedAt()).isBefore(Date.from(Instant.now()));
                }
        );
    }

    @Test
    public void informWithBloatedBomTest() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-bloated.json"));
        new BomUploadProcessingTask().inform(bomUploadEvent);

        assertThat(kafkaMockProducer.history())
                .anySatisfy(record -> {
                    assertThat(deserializeKey(KafkaTopics.NOTIFICATION_BOM, record)).isEqualTo(project.getUuid().toString());
                    assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                    final Notification notification = deserializeValue(KafkaTopics.NOTIFICATION_BOM, record);
                    assertThat(notification.getGroup()).isEqualTo(Group.GROUP_BOM_CONSUMED);
                })
                .anySatisfy(record -> {
                    assertThat(deserializeKey(KafkaTopics.NOTIFICATION_BOM, record)).isEqualTo(project.getUuid().toString());
                    assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                    final Notification notification = deserializeValue(KafkaTopics.NOTIFICATION_BOM, record);
                    assertThat(notification.getGroup()).isEqualTo(Group.GROUP_BOM_PROCESSED);
                })
                .noneSatisfy(record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                    final Notification notification = deserializeValue(KafkaTopics.NOTIFICATION_BOM, record);
                    assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
                });

        final List<Bom> boms = qm.getAllBoms(project);
        assertThat(boms).hasSize(1);
        final Bom bom = boms.get(0);
        assertThat(bom.getBomFormat()).isEqualTo("CycloneDX");
        assertThat(bom.getSpecVersion()).isEqualTo("1.3");
        assertThat(bom.getBomVersion()).isEqualTo(1);
        assertThat(bom.getSerialNumber()).isEqualTo("6d780157-0f8e-4ef1-8e9b-1eb48b2fad6f");

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getGroup()).isNull(); // Not overridden by BOM import
        assertThat(project.getName()).isEqualTo("Acme Example"); // Not overridden by BOM import
        assertThat(project.getVersion()).isEqualTo("1.0"); // Not overridden by BOM import
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getPurl()).isNotNull();
        assertThat(project.getPurl().canonicalize()).isEqualTo("pkg:npm/bloated@1.0.0");
        assertThat(project.getDirectDependencies()).isNotNull();

        // Make sure we ingested all components of the BOM.
        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(9056);

        // Assert some basic properties that should be present on all components.
        for (final Component component : components) {
            assertThat(component.getName()).isNotEmpty();
            assertThat(component.getVersion()).isNotEmpty();
            assertThat(component.getPurl()).isNotNull();
        }

        // Ensure dependency graph has been ingested completely, by asserting on the number leaf nodes of the graph.
        // This number can be verified using this Python script:
        //
        // import json
        // with open("bloated.bom.json", "r") as f:
        //     bom = json.load(f)
        // len(list(filter(lambda x: len(x.get("dependsOn", [])) == 0, bom["dependencies"])))
        final long componentsWithoutDirectDependencies = components.stream()
                .map(Component::getDirectDependencies)
                .filter(Objects::isNull)
                .count();
        assertThat(componentsWithoutDirectDependencies).isEqualTo(6378);

        // A VulnerabilityScan should've been initiated properly.
        final VulnerabilityScan vulnerabilityScan = qm.getVulnerabilityScan(bomUploadEvent.getChainIdentifier().toString());
        assertThat(vulnerabilityScan).isNotNull();
        assertThat(vulnerabilityScan.getTargetType()).isEqualTo(VulnerabilityScan.TargetType.PROJECT);
        assertThat(vulnerabilityScan.getTargetIdentifier()).isEqualTo(project.getUuid());
        assertThat(vulnerabilityScan.getExpectedResults()).isEqualTo(9056);
        assertThat(vulnerabilityScan.getReceivedResults()).isZero();

        // Verify that all vulnerability analysis commands have been sent.
        final long vulnAnalysisCommandsSent = kafkaMockProducer.history().stream()
                .map(ProducerRecord::topic)
                .filter(KafkaTopics.VULN_ANALYSIS_COMMAND.name()::equals)
                .count();
        assertThat(vulnAnalysisCommandsSent).isEqualTo(9056);

        // Verify that all repository meta analysis commands have been sent.
        final long repoMetaAnalysisCommandsSent = kafkaMockProducer.history().stream()
                .map(ProducerRecord::topic)
                .filter(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name()::equals)
                .count();
        assertThat(repoMetaAnalysisCommandsSent).isEqualTo(9056);
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/2519
    public void informIssue2519Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        
        // Upload the same BOM again a few times.
        // Ensure processing does not fail, and the number of components ingested doesn't change.
        for (int i = 0; i < 3; i++) {
            var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-issue2519.xml"));
            new BomUploadProcessingTask().inform(bomUploadEvent);

            // Make sure processing did not fail.
            assertThat(kafkaMockProducer.history())
                    .noneSatisfy(record -> {
                        assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                        final Notification notification = deserializeValue(KafkaTopics.NOTIFICATION_BOM, record);
                        assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
                    });

            // Ensure the expected amount of components is present.
            assertThat(qm.getAllComponents(project)).hasSize(1756);
        }
    }

    @Test // https://github.com/DependencyTrack/dependency-track/issues/1905
    public void informIssue1905Test() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        for (int i = 0; i < 3; i++) {
            var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), createTempBomFile("bom-issue1905.json"));
            new BomUploadProcessingTask().inform(bomUploadEvent);

            // Make sure processing did not fail.
            assertThat(kafkaMockProducer.history())
                    .noneSatisfy(record -> {
                        assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                        final Notification notification = deserializeValue(KafkaTopics.NOTIFICATION_BOM, record);
                        assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
                    });

            // Ensure all expected components are present.
            // In this particular case, both components from the BOM are supposed to NOT be merged.
            assertThat(qm.getAllComponents(project)).satisfiesExactlyInAnyOrder(
                    component -> {
                        assertThat(component.getClassifier()).isEqualTo(Classifier.LIBRARY);
                        assertThat(component.getName()).isEqualTo("cloud.google.com/go/storage");
                        assertThat(component.getVersion()).isEqualTo("v1.13.0");
                        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:golang/cloud.google.com/go/storage@v1.13.0?type=package");
                        assertThat(component.getSha256()).isNull();
                    },
                    component -> {
                        assertThat(component.getClassifier()).isEqualTo(Classifier.LIBRARY);
                        assertThat(component.getName()).isEqualTo("cloud.google.com/go/storage");
                        assertThat(component.getVersion()).isEqualTo("v1.13.0");
                        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:golang/cloud.google.com/go/storage@v1.13.0?goarch=amd64&goos=darwin&type=module");
                        assertThat(component.getSha256()).isEqualTo("6a63ef842388f8796da7aacfbbeeb661dc2122b8dffb7e0f29500be07c206309");
                    }
            );
        }
    }

    private static File createTempBomFile(final String testFileName) throws Exception {
        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(resourceToURL("/unit/" + testFileName).toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        return bomFilePath.toFile();
    }

}
