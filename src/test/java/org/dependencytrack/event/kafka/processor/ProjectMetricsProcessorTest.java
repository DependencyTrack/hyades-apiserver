package org.dependencytrack.event.kafka.processor;

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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.PersistenceManager;
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
    public void testProjectWithNoMetrics() {
        Project project = qm.createProject("testProject", null, null, null, null, null, true, true);
        ProjectMetrics projectMetrics = setProjectMetrics(1, 2, 3, 2, 5, 2);
        projectMetrics.setProject(project);
        inputTopic.pipeInput(project.getUuid().toString(), projectMetrics);
        qm.getPersistenceManager().refreshAll();
        ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getProject().getName()).isEqualTo(project.getName());
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getLow()).isZero();


    }

    @Test
    public void testProjectWithSameExistingMetrics() {
        final PersistenceManager pm = qm.getPersistenceManager();
        ProjectMetrics projectMetrics1 = setProjectMetrics(1,2,3,2,5,2);
        Project project = qm.createProject("testProject", null, null, null, null, null, true, true);
        projectMetrics1.setProject(project);
        qm.runInTransaction(() -> {
            projectMetrics1.setProject(project);
            pm.makePersistent(projectMetrics1);
        });
        ProjectMetrics projectMetrics = setProjectMetrics(1,2,3,2,5,2);
        projectMetrics.setProject(project);
        inputTopic.pipeInput(project.getUuid().toString(), projectMetrics);
        qm.getPersistenceManager().refreshAll();
        ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getProject().getName()).isEqualTo(project.getName());
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getLow()).isZero();
    }

    @Test
    public void testProjectWithDifferentExistingMetrics() {
        final PersistenceManager pm = qm.getPersistenceManager();
        ProjectMetrics projectMetrics1 = setProjectMetrics(0,0,0,0,0,0);
        Project project = qm.createProject("testProject", null, null, null, null, null, true, true);
        projectMetrics1.setProject(project);
        qm.runInTransaction(() -> {
            projectMetrics1.setProject(project);
            pm.makePersistent(projectMetrics1);
        });
        ProjectMetrics projectMetrics = setProjectMetrics(1,2,3,2,5,2);
        projectMetrics.setProject(project);
        inputTopic.pipeInput(project.getUuid().toString(), projectMetrics);
        qm.getPersistenceManager().refreshAll();
        ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getProject().getName()).isEqualTo(project.getName());
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getLow()).isZero();
    }

    public static ProjectMetrics setProjectMetrics(int critical, int high, int medium,
                                                   int unassigned, int findingsTotal, int findingsAudited) {
        ProjectMetrics projectMetrics = new ProjectMetrics();
        projectMetrics.setCritical(critical);
        projectMetrics.setHigh(high);
        projectMetrics.setMedium(medium);
        projectMetrics.setLow(0);
        projectMetrics.setUnassigned(unassigned);
        projectMetrics.setFindingsTotal(findingsTotal);
        projectMetrics.setFindingsAudited(findingsAudited);
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
        return projectMetrics;
    }

}
