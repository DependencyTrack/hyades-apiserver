package org.dependencytrack.event.kafka.processor;

import alpine.persistence.PaginatedResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyTestDriver;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.serialization.JacksonDeserializer;
import org.dependencytrack.event.kafka.serialization.JacksonSerializer;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Vulnerability;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.sql.Time;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class ProjectMetricsProcessorTest extends PersistenceCapableTest {
    private TopologyTestDriver testDriver;
    UUID uuid = UUID.fromString("426df471-eda9-429a-9172-2df8ed290b33");
    private TestInputTopic<String, ProjectMetrics> inputTopic;

    @Before
    public void setUp() throws JsonProcessingException {
        final var topology = new Topology();
        topology.addSource("sourceProcessor",
                new StringDeserializer(), new JacksonDeserializer<>(ProjectMetrics.class), "input-topic");
        topology.addProcessor("projectMetricsProcessor",
                ProjectMetricsProcessor::new, "sourceProcessor");

        testDriver = new TopologyTestDriver(topology);
        inputTopic = testDriver.createInputTopic("input-topic",
                new StringSerializer(), new JacksonSerializer<>());
    }


    @After
    public void tearDown() {
        if (testDriver != null) {
            testDriver.close();
        }
    }

    @Test
    public void processNewProjectMetricsEvent() {
        Project project = qm.createProject("testProject", null, null, null, null, null, true, true);
        ProjectMetrics projectMetrics = new ProjectMetrics();
        projectMetrics.setProject(project);
        projectMetrics.setCritical(1);
        projectMetrics.setHigh(2);
        projectMetrics.setMedium(3);
        projectMetrics.setLow(0);
        projectMetrics.setUnassigned(2);
        projectMetrics.setFindingsTotal(5);
        projectMetrics.setFindingsAudited(2);
        projectMetrics.setFirstOccurrence(new Date());
        projectMetrics.setFindingsUnaudited(0);
        projectMetrics.setPolicyViolationsFail(0);
        projectMetrics.setPolicyViolationsWarn(0);
        projectMetrics.setPolicyViolationsInfo(0);
        projectMetrics.setPolicyViolationsAudited(0);
        projectMetrics.setPolicyViolationsUnaudited(0);
        projectMetrics.setPolicyViolationsTotal(0);
        projectMetrics.setPolicyViolationsSecurityTotal(0);
        projectMetrics.setPolicyViolationsSecurityAudited(0);
        projectMetrics.setPolicyViolationsSecurityUnaudited(0);
        projectMetrics.setPolicyViolationsLicenseTotal(0);
        projectMetrics.setPolicyViolationsLicenseAudited(0);
        projectMetrics.setPolicyViolationsLicenseUnaudited(0);
        projectMetrics.setPolicyViolationsOperationalAudited(0);
        projectMetrics.setPolicyViolationsOperationalTotal(0);
        projectMetrics.setPolicyViolationsOperationalUnaudited(0);
        projectMetrics.setLastOccurrence(new Date(new Date().getTime() - (1000 * 60 * 60 * 24)));
        inputTopic.pipeInput(project.getUuid().toString(), projectMetrics);
        PaginatedResult metrics1 = qm.getProjectMetrics(project);
        assertThat(project).isNotNull();
        assertThat(project.getName()).isEqualTo("testProject");
        assertThat(project.getMetrics().getCritical()).isEqualTo(1);
//        assertThat(metaComponent.getNamespace()).isEqualTo("foo");
//        assertThat(metaComponent.getName()).isEqualTo("bar");
//        assertThat(metaComponent.getLatestVersion()).isEqualTo("1.2.4");
//        assertThat(metaComponent.getPublished()).isEqualTo(metaModel.getPublishedTimestamp());
//        assertThat(metaComponent.getLastCheck()).isAfterOrEqualTo(testStartTime);

    }

}
