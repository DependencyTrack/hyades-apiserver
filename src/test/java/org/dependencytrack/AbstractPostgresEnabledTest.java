package org.dependencytrack;

import alpine.Config;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.kafka.clients.producer.MockProducer;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.dependencytrack.persistence.QueryManager;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;

public abstract class AbstractPostgresEnabledTest {

    protected PostgreSQLContainer<?> postgresContainer;
    protected MockProducer<byte[], byte[]> kafkaMockProducer;
    protected QueryManager qm;

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @Before
    public void setUp() throws Exception {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"))
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withDatabaseName("dtrack");
        postgresContainer.start();

        final var dnProps = TestUtil.getDatanucleusProperties(postgresContainer.getJdbcUrl(),
                postgresContainer.getDriverClassName(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

        qm = new QueryManager();
        this.kafkaMockProducer = (MockProducer<byte[], byte[]>) KafkaProducerInitializer.getProducer();
    }

    @After
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
        KafkaProducerInitializer.tearDown();
    }
}
