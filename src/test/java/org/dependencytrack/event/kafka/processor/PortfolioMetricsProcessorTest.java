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
import org.dependencytrack.model.PortfolioMetrics;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.jdo.PersistenceManager;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class PortfolioMetricsProcessorTest extends PersistenceCapableTest {
    private TopologyTestDriver testDriver;
    private TestInputTopic<String, PortfolioMetrics> inputTopic;

    @Before
    public void setUp() throws JsonProcessingException {
        final var topology = new Topology();
        topology.addSource("sourceProcessor",
                new StringDeserializer(), new JacksonDeserializer<>(PortfolioMetrics.class), "input-topic");
        topology.addProcessor("projectMetricsProcessor",
                PortfolioMetricsProcessor::new, "sourceProcessor");

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
    public void testPortfolioWithNoMetrics() {
        PortfolioMetrics portfolioMetrics = setPortfolioMetrics(1, 0, 0, 0, 0, 0, 1, 1);

        inputTopic.pipeInput("1", portfolioMetrics);
        qm.getPersistenceManager().refreshAll();
        PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getProjects()).isEqualTo(1);
        assertThat(metrics.getVulnerableProjects()).isEqualTo(1);
    }

    @Test
    public void testPortfolioMetricsWithSameExistingMetrics() {
        final PersistenceManager pm = qm.getPersistenceManager();
        PortfolioMetrics portfolioMetrics1 = setPortfolioMetrics(1, 2, 3, 2, 5, 2, 2, 1);
        qm.runInTransaction(() -> {
            pm.makePersistent(portfolioMetrics1);
        });
        PortfolioMetrics portfolioMetrics = setPortfolioMetrics(1, 2, 3, 2, 5, 2, 2, 1);
        inputTopic.pipeInput("1", portfolioMetrics);
        qm.getPersistenceManager().refreshAll();
        PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
        assertThat(metrics.getCritical()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(2);
        assertThat(metrics.getMedium()).isEqualTo(3);
        assertThat(metrics.getProjects()).isEqualTo(2);
        assertThat(metrics.getVulnerableProjects()).isEqualTo(1);
    }

    @Test
    public void testProjectWithDifferentExistingMetrics() {
        final PersistenceManager pm = qm.getPersistenceManager();
        PortfolioMetrics portfolioMetrics1 = setPortfolioMetrics(1, 2, 3, 0, 0, 0, 0, 0);
        qm.runInTransaction(() -> {
            pm.makePersistent(portfolioMetrics1);
        });
        PortfolioMetrics portfolioMetrics = setPortfolioMetrics(4, 5, 6, 2, 5, 2, 3, 1);
        inputTopic.pipeInput("1", portfolioMetrics);
        qm.getPersistenceManager().refreshAll();
        PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
        assertThat(metrics.getCritical()).isEqualTo(4);
        assertThat(metrics.getHigh()).isEqualTo(5);
        assertThat(metrics.getMedium()).isEqualTo(6);
        assertThat(metrics.getProjects()).isEqualTo(3);
        assertThat(metrics.getVulnerableProjects()).isEqualTo(1);
    }

    public static PortfolioMetrics setPortfolioMetrics(int critical, int high, int medium,
                                                       int unassigned, int findingsTotal, int findingsAudited,
                                                       int projects, int vulnerableProjects) {
        PortfolioMetrics portfolioMetrics = new PortfolioMetrics();
        portfolioMetrics.setCritical(critical);
        portfolioMetrics.setHigh(high);
        portfolioMetrics.setMedium(medium);
        portfolioMetrics.setLow(0);
        portfolioMetrics.setUnassigned(unassigned);
        portfolioMetrics.setFindingsTotal(findingsTotal);
        portfolioMetrics.setFindingsAudited(findingsAudited);
        portfolioMetrics.setFirstOccurrence(new Date());
        portfolioMetrics.setFindingsUnaudited(0);
        portfolioMetrics.setPolicyViolationsFail(0);
        portfolioMetrics.setPolicyViolationsWarn(0);
        portfolioMetrics.setProjects(projects);
        portfolioMetrics.setVulnerableProjects(vulnerableProjects);
        portfolioMetrics.setPolicyViolationsInfo(0);
        portfolioMetrics.setPolicyViolationsAudited(0);
        portfolioMetrics.setPolicyViolationsUnaudited(0);
        portfolioMetrics.setPolicyViolationsTotal(0);
        portfolioMetrics.setPolicyViolationsSecurityTotal(0);
        portfolioMetrics.setPolicyViolationsSecurityAudited(0);
        portfolioMetrics.setPolicyViolationsSecurityUnaudited(0);
        portfolioMetrics.setPolicyViolationsLicenseTotal(0);
        portfolioMetrics.setPolicyViolationsLicenseAudited(0);
        portfolioMetrics.setPolicyViolationsLicenseUnaudited(0);
        portfolioMetrics.setPolicyViolationsOperationalAudited(0);
        portfolioMetrics.setPolicyViolationsOperationalTotal(0);
        portfolioMetrics.setPolicyViolationsOperationalUnaudited(0);
        portfolioMetrics.setLastOccurrence(new Date(new Date().getTime() - (1000 * 60 * 60 * 24)));
        return portfolioMetrics;
    }

}
