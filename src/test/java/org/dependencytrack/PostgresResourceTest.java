package org.dependencytrack;

import alpine.Config;
import alpine.server.persistence.PersistenceManagerFactory;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.dependencytrack.persistence.migration.MigrationInitializer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.jdo.JDOHelper;
import java.sql.Connection;
import java.sql.Statement;

public abstract class PostgresResourceTest extends ResourceTest {

    protected static PostgreSQLContainer<?> postgresContainer;


    @BeforeClass
    public static void setUpClass() throws Exception {
        Config.enableUnitTests();

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
    }

    @Override
    public void before() throws Exception {
        // Truncate all tables to ensure each test starts from a clean slate.
        // https://stackoverflow.com/a/63227261
        try (final Connection connection = postgresContainer.createConnection("");
             final Statement statement = connection.createStatement()) {
            statement.execute("""
                    DO $$ DECLARE
                        r RECORD;
                    BEGIN
                        FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = CURRENT_SCHEMA()) LOOP
                            EXECUTE 'TRUNCATE TABLE ' || QUOTE_IDENT(r.tablename) || ' CASCADE';
                        END LOOP;
                    END $$;
                    """);
        }

        PersistenceManagerFactory.setJdoPersistenceManagerFactory(createPmf());

        super.before();
    }

    @AfterClass
    public static void tearDownClass() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    protected JDOPersistenceManagerFactory createPmf() {
        final var dnProps = TestUtil.getDatanucleusProperties(postgresContainer.getJdbcUrl(),
                postgresContainer.getDriverClassName(),
                postgresContainer.getUsername(),
                postgresContainer.getPassword());

        return (JDOPersistenceManagerFactory) JDOHelper.getPersistenceManagerFactory(dnProps, "Alpine");
    }

}
