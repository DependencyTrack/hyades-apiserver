package org.dependencytrack.tasks;

import org.apache.commons.io.IOUtils;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.BomUploadEvent;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.util.KafkaTestUtil;
import org.hyades.proto.notification.v1.Group;
import org.hyades.proto.notification.v1.Notification;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.Query;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class BomUploadProcessingTaskPerfTest extends PersistenceCapableTest {

    @Before
    public void setUp() {
        // Enable processing of CycloneDX BOMs
        qm.createConfigProperty(ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(), "true",
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX.getDescription());
    }

    @Test
    public void informTest() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(IOUtils.resourceToURL("/bloated.bom.json").toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        final var bomFile = bomFilePath.toFile();

        final var bomUploadEvent = new BomUploadEvent(project.getUuid(), bomFile);
        new BomUploadProcessingTask().inform(bomUploadEvent);

        await()
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(kafkaMockProducer.history())
                        .anySatisfy(record -> {
                            assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_BOM.name());
                            final Notification notification = KafkaTestUtil.deserializeValue(KafkaTopics.NOTIFICATION_BOM, record);
                            assertThat(notification.getGroup()).isEqualTo(Group.GROUP_BOM_PROCESSED);
                        }));

        // Make sure we ingested all components of the BOM.
        final Query<Component> componentCountQuery = qm.getPersistenceManager().newQuery(Component.class);
        componentCountQuery.setFilter("project == :project");
        assertThat(qm.getCount(componentCountQuery, project)).isEqualTo(9056);

        // Verify that we're not getting slower than before.
        assertThat(BomUploadProcessingTask.TIMER.totalTime(TimeUnit.SECONDS)).isLessThan(25);
    }

    @Test
    public void informTestX() throws Exception {
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // The task will delete the input file after processing it,
        // so create a temporary copy to not impact other tests.
        final Path bomFilePath = Files.createTempFile(null, null);
        Files.copy(Paths.get(IOUtils.resourceToURL("/bloated.bom.json").toURI()), bomFilePath, StandardCopyOption.REPLACE_EXISTING);
        final var bomFile = bomFilePath.toFile();

        final var bomUploadEvent = new BomUploadEvent(project.getUuid(), bomFile);
        new BomUploadProcessingTask().process(bomUploadEvent);

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getName()).isEqualTo("Acme Example");
        assertThat(project.getVersion()).isEqualTo("1.0");
        assertThat(project.getDescription()).isNull();
        assertThat(project.getPurl().canonicalize()).isEqualTo("pkg:npm/bloated@1.0.0");

        // Make sure we ingested all components of the BOM.
        final Query<Component> componentCountQuery = qm.getPersistenceManager().newQuery(Component.class);
        componentCountQuery.setFilter("project == :project");
        assertThat(qm.getCount(componentCountQuery, project)).isEqualTo(9056);

        // Verify that we're not getting slower than before.
        assertThat(BomUploadProcessingTask.TIMER.totalTime(TimeUnit.SECONDS)).isLessThan(25);
    }

}
