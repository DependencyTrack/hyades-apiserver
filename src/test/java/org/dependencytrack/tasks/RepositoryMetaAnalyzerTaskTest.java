package org.dependencytrack.tasks;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.PortfolioRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.ProjectRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.kafka.KafkaTopic;
import org.dependencytrack.model.Component;
import org.dependencytrack.tasks.RepositoryMetaAnalyzerTask;
import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

public class RepositoryMetaAnalyzerTaskTest extends PersistenceCapableTest {

    @Test
    public void testPortfolioRepositoryMetaAnalysis() {
        // Create an active project with one component.
        final var projectA = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentProjectA = new Component();
        componentProjectA.setProject(projectA);
        componentProjectA.setGroup("acme");
        componentProjectA.setName("acme-lib-a");
        componentProjectA.setVersion("1.0.1");
        componentProjectA.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
        qm.persist(componentProjectA);

        // Create another active project with one component.
        final var projectB = qm.createProject("acme-app-b", null, "2.0.0", null, null, null, true, false);
        final var componentProjectB = new Component();
        componentProjectB.setProject(projectB);
        componentProjectB.setGroup("acme");
        componentProjectB.setName("acme-lib-b");
        componentProjectB.setVersion("2.0.1");
        componentProjectB.setCpe("cpe:2.3:a:acme:acme-lib-b:2.0.1:*:*:*:*:*:*:*");
        qm.persist(componentProjectB);

        // Create an inactive project with one component.
        final var projectC = qm.createProject("acme-app-c", null, "3.0.0", null, null, null, false, false);
        final var componentProjectC = new Component();
        componentProjectC.setProject(projectC);
        componentProjectC.setGroup("acme");
        componentProjectC.setName("acme-lib-c");
        componentProjectC.setVersion("3.0.1");
        qm.persist(componentProjectC);

        new RepositoryMetaAnalyzerTask().inform(new PortfolioRepositoryMetaAnalysisEvent());

        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopic.NOTIFICATION_PROJECT_CREATED.getName()),
                record -> assertThat(record.topic()).isEqualTo(KafkaTopic.NOTIFICATION_PROJECT_CREATED.getName()),
                record -> assertThat(record.topic()).isEqualTo(KafkaTopic.NOTIFICATION_PROJECT_CREATED.getName()),
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopic.REPO_META_ANALYSIS_COMPONENT.getName());
                    final var eventComponent = (org.dependencytrack.event.kafka.dto.Component) record.value();
                    assertThat(eventComponent.uuid()).isEqualTo(componentProjectB.getUuid());
                    assertThat(eventComponent.group()).isEqualTo(componentProjectB.getGroup());
                    assertThat(eventComponent.name()).isEqualTo(componentProjectB.getName());
                    assertThat(eventComponent.version()).isEqualTo(componentProjectB.getVersion());
                    assertThat(eventComponent.cpe()).isNull();
                    assertThat(eventComponent.purl()).isNull();
                },
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopic.REPO_META_ANALYSIS_COMPONENT.getName());
                    final var eventComponent = (org.dependencytrack.event.kafka.dto.Component) record.value();
                    assertThat(eventComponent.uuid()).isEqualTo(componentProjectA.getUuid());
                    assertThat(eventComponent.group()).isEqualTo(componentProjectA.getGroup());
                    assertThat(eventComponent.name()).isEqualTo(componentProjectA.getName());
                    assertThat(eventComponent.version()).isEqualTo(componentProjectA.getVersion());
                    assertThat(eventComponent.cpe()).isNull();
                    assertThat(eventComponent.purl()).isEqualTo(componentProjectA.getPurl().toString());
                }
                // Component of inactive project must not have been submitted for analysis
        );
    }

    @Test
    public void testProjectRepositoryMetaAnalysis() {
        final var project = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, true, false);
        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setGroup("acme");
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.0.1");
        componentA.setPurl("pkg:maven/acme/acme-lib-a@1.0.1?foo=bar");
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
        qm.persist(componentC);

        new RepositoryMetaAnalyzerTask().inform(new ProjectRepositoryMetaAnalysisEvent(project.getUuid()));

        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopic.NOTIFICATION_PROJECT_CREATED.getName()),
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopic.REPO_META_ANALYSIS_COMPONENT.getName());
                    final var eventComponent = (org.dependencytrack.event.kafka.dto.Component) record.value();
                    assertThat(eventComponent.uuid()).isEqualTo(componentC.getUuid());
                    assertThat(eventComponent.group()).isEqualTo(componentC.getGroup());
                    assertThat(eventComponent.name()).isEqualTo(componentC.getName());
                    assertThat(eventComponent.version()).isEqualTo(componentC.getVersion());
                    assertThat(eventComponent.cpe()).isNull();
                    assertThat(eventComponent.purl()).isEqualTo(componentC.getPurl().toString());
                },
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopic.REPO_META_ANALYSIS_COMPONENT.getName());
                    final var eventComponent = (org.dependencytrack.event.kafka.dto.Component) record.value();
                    assertThat(eventComponent.uuid()).isEqualTo(componentB.getUuid());
                    assertThat(eventComponent.group()).isEqualTo(componentB.getGroup());
                    assertThat(eventComponent.name()).isEqualTo(componentB.getName());
                    assertThat(eventComponent.version()).isEqualTo(componentB.getVersion());
                    assertThat(eventComponent.cpe()).isNull();
                    assertThat(eventComponent.purl()).isNull();
                },
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopic.REPO_META_ANALYSIS_COMPONENT.getName());
                    final var eventComponent = (org.dependencytrack.event.kafka.dto.Component) record.value();
                    assertThat(eventComponent.uuid()).isEqualTo(componentA.getUuid());
                    assertThat(eventComponent.group()).isEqualTo(componentA.getGroup());
                    assertThat(eventComponent.name()).isEqualTo(componentA.getName());
                    assertThat(eventComponent.version()).isEqualTo(componentA.getVersion());
                    assertThat(eventComponent.cpe()).isNull();
                    assertThat(eventComponent.purl()).isEqualTo(componentA.getPurl().toString());
                }
        );
    }

    @Test
    public void testProjectRepositoryMetaAnalysisWithInactiveProject() {
        final var project = qm.createProject("acme-app-a", null, "1.0.0", null, null, null, false, false);
        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.0.1");
        qm.persist(componentA);

        new RepositoryMetaAnalyzerTask().inform(new ProjectRepositoryMetaAnalysisEvent(project.getUuid()));

        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopic.NOTIFICATION_PROJECT_CREATED.getName())
                // Component of inactive project must not have been submitted for analysis
        );
    }

    @Test
    public void testProjectRepositoryMetaAnalysisWithNonExistentProject() {
        assertThatNoException()
                .isThrownBy(() -> new RepositoryMetaAnalyzerTask().inform(new ProjectRepositoryMetaAnalysisEvent(UUID.randomUUID())));
    }

}