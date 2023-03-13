package org.dependencytrack.event.kafka.processor;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.TopologyTestDriver;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufDeserializer;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.hyades.proto.metrics.v1.FindingsMetrics;
import org.hyades.proto.metrics.v1.PolicyViolationsMetrics;
import org.hyades.proto.metrics.v1.VulnerabilitiesMetrics;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class ProjectMetricsProcessorTest extends PersistenceCapableTest {

    private TopologyTestDriver testDriver;
    private TestInputTopic<String, org.hyades.proto.metrics.v1.ProjectMetrics> inputTopic;

    @Before
    public void setUp() throws JsonProcessingException {
        final var topology = new Topology();
        topology.addSource("sourceProcessor",
                new StringDeserializer(), new KafkaProtobufDeserializer<>(org.hyades.proto.metrics.v1.ProjectMetrics.parser()), "input-topic");
        topology.addProcessor("projectMetricsProcessor",
                ProjectMetricsProcessor::new, "sourceProcessor");

        testDriver = new TopologyTestDriver(topology);
        inputTopic = testDriver.createInputTopic("input-topic",
                new StringSerializer(), new KafkaProtobufSerializer<>());
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
        var eventMetrics = org.hyades.proto.metrics.v1.ProjectMetrics.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .setComponents(2)
                .setVulnerableComponents(1)
                .setVulnerabilities(VulnerabilitiesMetrics.newBuilder()
                        .setTotal(8)
                        .setCritical(1)
                        .setHigh(2)
                        .setMedium(3)
                        .setUnassigned(2))
                .setFindings(FindingsMetrics.newBuilder()
                        .setTotal(8)
                        .setAudited(2)
                        .setUnaudited(6))
                .setPolicyViolations(PolicyViolationsMetrics.newBuilder()
                        .setTotal(9)
                        .setFail(3)
                        .setWarn(3)
                        .setInfo(3)
                        .setAudited(3)
                        .setUnaudited(6)
                        .setLicenseTotal(3)
                        .setLicenseAudited(1)
                        .setLicenseUnaudited(2)
                        .setOperationalTotal(3)
                        .setOperationalAudited(1)
                        .setOperationalUnaudited(2)
                        .setSecurityTotal(3)
                        .setSecurityAudited(1)
                        .setSecurityUnaudited(2))
                .build();

        inputTopic.pipeInput(project.getUuid().toString(), eventMetrics);

        ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getComponents()).isEqualTo(2);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(1);
        assertThat(metrics.getVulnerabilities()).isEqualTo(8);
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isEqualTo(2);
        assertThat(metrics.getFindingsTotal()).isEqualTo(8);
        assertThat(metrics.getFindingsAudited()).isEqualTo(2);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(6);
        assertThat(metrics.getPolicyViolationsTotal()).isEqualTo(9);
        assertThat(metrics.getPolicyViolationsFail()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsWarn()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsInfo()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsAudited()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsUnaudited()).isEqualTo(6);
        assertThat(metrics.getPolicyViolationsLicenseTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsLicenseAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsOperationalTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsSecurityTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsSecurityAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isEqualTo(2);
        assertThat(metrics.getFirstOccurrence()).hasSameTimeAs(metrics.getLastOccurrence());
    }

    @Test
    public void testProjectWithSameExistingMetrics() {
        Project project = qm.createProject("testProject", null, null, null, null, null, true, true);
        var eventMetrics = org.hyades.proto.metrics.v1.ProjectMetrics.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .setComponents(2)
                .setVulnerableComponents(1)
                .setVulnerabilities(VulnerabilitiesMetrics.newBuilder()
                        .setTotal(8)
                        .setCritical(1)
                        .setHigh(2)
                        .setMedium(3)
                        .setUnassigned(2))
                .setFindings(FindingsMetrics.newBuilder()
                        .setTotal(8)
                        .setAudited(2)
                        .setUnaudited(6))
                .setPolicyViolations(PolicyViolationsMetrics.newBuilder()
                        .setTotal(9)
                        .setFail(3)
                        .setWarn(3)
                        .setInfo(3)
                        .setAudited(3)
                        .setUnaudited(6)
                        .setLicenseTotal(3)
                        .setLicenseAudited(1)
                        .setLicenseUnaudited(2)
                        .setOperationalTotal(3)
                        .setOperationalAudited(1)
                        .setOperationalUnaudited(2)
                        .setSecurityTotal(3)
                        .setSecurityAudited(1)
                        .setSecurityUnaudited(2))
                .build();

        var eventTime1 = Instant.ofEpochSecond(1678720347);
        var eventTime2 = Instant.ofEpochSecond(1678720400);

        inputTopic.pipeInput(project.getUuid().toString(), eventMetrics, eventTime1);
        inputTopic.pipeInput(project.getUuid().toString(), eventMetrics, eventTime2);

        ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getComponents()).isEqualTo(2);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(1);
        assertThat(metrics.getVulnerabilities()).isEqualTo(8);
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isEqualTo(2);
        assertThat(metrics.getFindingsTotal()).isEqualTo(8);
        assertThat(metrics.getFindingsAudited()).isEqualTo(2);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(6);
        assertThat(metrics.getPolicyViolationsTotal()).isEqualTo(9);
        assertThat(metrics.getPolicyViolationsFail()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsWarn()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsInfo()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsAudited()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsUnaudited()).isEqualTo(6);
        assertThat(metrics.getPolicyViolationsLicenseTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsLicenseAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsOperationalTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsSecurityTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsSecurityAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isEqualTo(2);
        assertThat(metrics.getFirstOccurrence()).isEqualTo(eventTime1);
        assertThat(metrics.getLastOccurrence()).isEqualTo(eventTime2);
    }

    @Test
    public void testProjectWithDifferentExistingMetrics() {
        Project project = qm.createProject("testProject", null, null, null, null, null, true, true);
        var eventMetrics1 = org.hyades.proto.metrics.v1.ProjectMetrics.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .build();
        var eventMetrics2 = org.hyades.proto.metrics.v1.ProjectMetrics.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .setComponents(2)
                .setVulnerableComponents(1)
                .setVulnerabilities(VulnerabilitiesMetrics.newBuilder()
                        .setTotal(8)
                        .setCritical(1)
                        .setHigh(2)
                        .setMedium(3)
                        .setUnassigned(2))
                .setFindings(FindingsMetrics.newBuilder()
                        .setTotal(8)
                        .setAudited(2)
                        .setUnaudited(6))
                .setPolicyViolations(PolicyViolationsMetrics.newBuilder()
                        .setTotal(9)
                        .setFail(3)
                        .setWarn(3)
                        .setInfo(3)
                        .setAudited(3)
                        .setUnaudited(6)
                        .setLicenseTotal(3)
                        .setLicenseAudited(1)
                        .setLicenseUnaudited(2)
                        .setOperationalTotal(3)
                        .setOperationalAudited(1)
                        .setOperationalUnaudited(2)
                        .setSecurityTotal(3)
                        .setSecurityAudited(1)
                        .setSecurityUnaudited(2))
                .build();

        var eventTime1 = Instant.ofEpochSecond(1678720347);
        var eventTime2 = Instant.ofEpochSecond(1678720400);

        inputTopic.pipeInput(project.getUuid().toString(), eventMetrics1, eventTime1);
        inputTopic.pipeInput(project.getUuid().toString(), eventMetrics2, eventTime2);

        qm.getPersistenceManager().refresh(project);
        ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getComponents()).isEqualTo(2);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(1);
        assertThat(metrics.getVulnerabilities()).isEqualTo(8);
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isEqualTo(2);
        assertThat(metrics.getFindingsTotal()).isEqualTo(8);
        assertThat(metrics.getFindingsAudited()).isEqualTo(2);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(6);
        assertThat(metrics.getPolicyViolationsTotal()).isEqualTo(9);
        assertThat(metrics.getPolicyViolationsFail()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsWarn()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsInfo()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsAudited()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsUnaudited()).isEqualTo(6);
        assertThat(metrics.getPolicyViolationsLicenseTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsLicenseAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsOperationalTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsSecurityTotal()).isEqualTo(3);
        assertThat(metrics.getPolicyViolationsSecurityAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isEqualTo(2);
        assertThat(metrics.getFirstOccurrence()).isEqualTo(eventTime2);
        assertThat(metrics.getLastOccurrence()).isEqualTo(eventTime2);
    }

}
