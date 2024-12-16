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
package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.PortfolioRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ProjectRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Component;
import org.junit.Test;

import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;

public class RepositoryMetaAnalysisTaskTest extends PersistenceCapableTest {

    @Test
    public void testPortfolioRepositoryMetaAnalysis() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentProjectA = new Component();
        componentProjectA.setProject(projectA);
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        componentProjectA.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        qm.persist(componentProjectA);

        // Create another active project with one component.
        final var projectB = qm.createProject("acme-app-b", null, "2.0.0", null, null, null, null, false);
        final var componentProjectB = new Component();
        componentProjectB.setProject(projectB);
        componentProjectB.setName("acme-lib-b");
        componentProjectB.setVersion("2.0.1");
        componentProjectB.setCpe("cpe:2.3:a:acme:acme-lib-b:2.0.1:*:*:*:*:*:*:*");
        qm.persist(componentProjectB);

        // Create an inactive project with one component.
        final var projectC = qm.createProject("acme-app-c", null, "3.0.0", null, null, null, new Date(), false);
        final var componentProjectC = new Component();
        componentProjectC.setProject(projectC);
        componentProjectC.setName("acme-lib-c");
        componentProjectC.setVersion("3.0.1");
        componentProjectC.setPurl("pkg:maven/acme/acme-lib-c@3.0.1?foo=bar");
        componentProjectC.setPurlCoordinates("pkg:maven/acme/acme-lib-c@3.0.1");
        qm.persist(componentProjectC);

        // Create an active project with a component that has identical purlCoordinates as componentProjectA.
        final var projectD = qm.createProject("acme-app-d", null, "4.0.0", null, null, null, null, false);
        final var componentProjectD = new Component();
        componentProjectD.setProject(projectD);
        componentProjectD.setName("acme-lib-a");
        componentProjectD.setVersion("1.0.1");
        componentProjectD.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?qux=quux");
        componentProjectD.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        qm.persist(componentProjectD);

        // Create an active project with a component that has identical purlCoordinates as componentProjectA, but is internal.
        final var projectE = qm.createProject("acme-app-e", null, "5.0.0", null, null, null, null, false);
        final var componentProjectE = new Component();
        componentProjectE.setProject(projectE);
        componentProjectE.setName("acme-lib-a");
        componentProjectE.setVersion("1.0.1");
        componentProjectE.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?fizz=buzz");
        componentProjectE.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        componentProjectE.setInternal(true);
        qm.persist(componentProjectE);

        new RepositoryMetaAnalysisTask().inform(new PortfolioRepositoryMetaAnalysisEvent());

        assertThat(kafkaMockProducer.history()).satisfiesExactlyInAnyOrder(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()), // projectA
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()), // projectB
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()), // projectC
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()), // projectD
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()), // projectE
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/acme/acme-lib-a@1.0.1");
                    assertThat(command.getComponent().getInternal()).isFalse();
                },
                // componentProjectB must not have been submitted, because it does not have a PURL
                // componentProjectC must not have been submitted, because it belongs to an inactive project
                // componentProjectD has the same PURL coordinates as componentProjectA and is not submitted again
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/acme/acme-lib-a@1.0.1");
                    assertThat(command.getComponent().getInternal()).isTrue();
                }
        );
    }

    @Test
    public void testProjectRepositoryMetaAnalysis() {
        final var project = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, null, false);
        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setGroup("acme");
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.0.1");
        componentA.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        componentA.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        qm.persist(componentA);
        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setGroup("acme");
        componentB.setName("acme-lib-b");
        componentB.setVersion("2.0.1");
        componentB.setCpe("cpe:2.3:a:acme:acme-lib-b:2.0.1:*:*:*:*:*:*:*");
        qm.persist(componentB);
        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setGroup("acme");
        componentC.setName("acme-lib-c");
        componentC.setVersion("3.0.1");
        componentC.setCpe("cpe:2.3:a:acme:acme-lib-c:3.0.1:*:*:*:*:*:*:*");
        componentC.setPurl("pkg:maven/acme/acme-lib-c@3.0.1?foo=bar");
        componentC.setPurlCoordinates("pkg:maven/acme/acme-lib-c@3.0.1");
        qm.persist(componentC);
        final var componentD = new Component();
        componentD.setProject(project);
        componentD.setGroup("acme");
        componentD.setName("acme-lib-a");
        componentD.setVersion("1.0.1");
        componentD.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?qux=quux");
        componentD.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        qm.persist(componentD);
        final var componentE = new Component();
        componentE.setProject(project);
        componentE.setGroup("acme");
        componentE.setName("acme-lib-a");
        componentE.setVersion("1.0.1");
        componentE.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?qux=quux");
        componentE.setPurlCoordinates("pkg:maven/acme/acme-lib-a@1.0.1");
        componentE.setInternal(true);
        qm.persist(componentE);

        new RepositoryMetaAnalysisTask().inform(new ProjectRepositoryMetaAnalysisEvent(project.getUuid()));

        assertThat(kafkaMockProducer.history()).satisfiesExactlyInAnyOrder(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/acme/acme-lib-a@1.0.1");
                    assertThat(command.getComponent().getInternal()).isFalse();
                },
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/acme/acme-lib-a@1.0.1");
                    assertThat(command.getComponent().getInternal()).isTrue();
                },
                // componentB must not have been submitted, because it does not have a PURL
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo("pkg:maven/acme/acme-lib-c@3.0.1");
                    assertThat(command.getComponent().getInternal()).isFalse();
                }
                // componentD has the same PURL coordinates as componentA nad is not submitted again
        );
    }

    @Test
    public void testProjectRepositoryMetaAnalysisWithInactiveProject() {
        final var project = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, new Date(), false);
        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.0.1");
        qm.persist(componentA);

        new RepositoryMetaAnalysisTask().inform(new ProjectRepositoryMetaAnalysisEvent(project.getUuid()));

        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name())
                // Component of inactive project must not have been submitted for analysis
        );
    }

    @Test
    public void testProjectRepositoryMetaAnalysisWithNonExistentProject() {
        assertThatNoException()
                .isThrownBy(() -> new RepositoryMetaAnalysisTask().inform(new ProjectRepositoryMetaAnalysisEvent(UUID.randomUUID())));
    }

}