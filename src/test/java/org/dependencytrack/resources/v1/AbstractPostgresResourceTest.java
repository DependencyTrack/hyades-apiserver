package org.dependencytrack.resources.v1;

import alpine.Config;
import alpine.model.Permission;
import alpine.server.persistence.PersistenceManagerFactory;
import org.apache.kafka.clients.producer.MockProducer;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.TestUtil;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.migration.MigrationInitializer;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.util.ArrayList;
import java.util.List;

public class AbstractPostgresResourceTest extends ResourceTest {
    protected PostgreSQLContainer<?> postgresContainer;
    protected MockProducer<byte[], byte[]> kafkaMockProducer;
    protected QueryManager qm;

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @BeforeClass
    public static void init() {
        Config.enableUnitTests();
    }

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"))
                .withUsername("dtrack")
                .withPassword("dtrack")
                .withDatabaseName("dtrack");
        postgresContainer.start();

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        MigrationInitializer.runMigration(dataSource, /* silent */ true);

        final var dnProps = TestUtil.getDatanucleusProperties(postgresContainer.getJdbcUrl(),
                postgresContainer.getDriverClassName(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());

        final var pmf = (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
        PersistenceManagerFactory.tearDown();
        PersistenceManagerFactory.setJdoPersistenceManagerFactory(pmf);

        qm = new QueryManager();
        this.kafkaMockProducer = (MockProducer<byte[], byte[]>) KafkaProducerInitializer.getProducer();
    }

    @AfterEach
    public void tearDown() throws Exception {
        super.tearDown();
        if (!qm.getPersistenceManager().isClosed()
                && qm.getPersistenceManager().currentTransaction().isActive()) {
            qm.getPersistenceManager().currentTransaction().rollback();
        }

        PersistenceManagerFactory.tearDown();
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
        KafkaProducerInitializer.tearDown();
    }

    public void initializeWithPermissions(Permissions... permissions) {
        List<Permission> permissionList = new ArrayList<>();
        for (Permissions permission : permissions) {
            permissionList.add(qm.createPermission(permission.name(), null));
        }
        testUser.setPermissions(permissionList);
        team.setPermissions(permissionList);
        qm.persist(team);
        testUser = qm.persist(testUser);
    }
}
