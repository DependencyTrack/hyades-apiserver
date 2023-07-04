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

import org.apache.commons.io.IOUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.util.KafkaTestUtil;
import org.hyades.proto.notification.v1.BomProcessingFailedSubject;
import org.hyades.proto.notification.v1.Notification;
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;
import static org.hyades.proto.notification.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.hyades.proto.notification.v1.Level.LEVEL_ERROR;
import static org.hyades.proto.notification.v1.Scope.SCOPE_PORTFOLIO;

public class BomUploadProcessingTaskTest extends PersistenceCapableTest {

    @Before
    public void setUp() {
        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());

        // Enable internal vulnerability analyzer
        qm.createConfigProperty(ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getGroupName(),
                ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getPropertyName(), "true",
                ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getPropertyType(),
                ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED.getDescription());
    }

    @Test
    public void informTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(IOUtils.resourceToURL("/bom-1.xml").toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        final var bomFile = bomFilePath.toFile();

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomFile);
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

        final VulnerabilityScan vulnerabilityScan = qm.getVulnerabilityScan(bomUploadEvent.getChainIdentifier().toString());
        assertThat(vulnerabilityScan).isNotNull();
    }

    @Test
    public void informWithEmptyBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(IOUtils.resourceToURL("/unit/bom-empty.json").toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        final var bomFile = bomFilePath.toFile();

        final var bomUploadEvent = new BomUploadEvent(qm.detach(Project.class, project.getId()), bomFile);
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

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();

        final VulnerabilityScan vulnerabilityScan = qm.getVulnerabilityScan(bomUploadEvent.getChainIdentifier().toString());
        assertThat(vulnerabilityScan).isNull();
    }

    @Test
    public void informWithInvalidBomTest() throws Exception {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(IOUtils.resourceToURL("/unit/bom-invalid.json").toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        final var bomFile = bomFilePath.toFile();

        new BomUploadProcessingTask().inform(new BomUploadEvent(qm.detach(Project.class, project.getId()), bomFile));
        assertConditionWithTimeout(() -> kafkaMockProducer.history().size() >= 2, Duration.ofSeconds(5));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                event -> assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                event -> {
                    assertThat(event.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                    final Notification notification = KafkaTestUtil.deserializeValue(KafkaTopics.NOTIFICATION_BOM, event);
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
        assertThat(project.getClassifier()).isNull();
        assertThat(project.getLastBomImport()).isNull();
        assertThat(project.getExternalReferences()).isNull();
        assertThat(project.getExternalReferences()).isNull();

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).isEmpty();
    }

}
