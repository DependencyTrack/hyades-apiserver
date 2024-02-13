package org.dependencytrack;

import com.github.dockerjava.api.command.InspectContainerResponse;
import org.dependencytrack.persistence.migration.MigrationInitializer;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

public class PostgresTestContainer extends PostgreSQLContainer<PostgresTestContainer> {

    @SuppressWarnings("resource")
    public PostgresTestContainer() {
        super(DockerImageName.parse("postgres:11-alpine"));
        withUsername("dtrack");
        withPassword("dtrack");
        withDatabaseName("dtrack");
        withLabel("owner", "hyades-apiserver");

        // NB: Container reuse won't be active unless either:
        //  - The environment variable TESTCONTAINERS_REUSE_ENABLE=true is set
        //  - testcontainers.reuse.enable=false is set in ~/.testcontainers.properties
        withReuse(true);
    }

    @Override
    protected void containerIsStarted(final InspectContainerResponse containerInfo, final boolean reused) {
        super.containerIsStarted(containerInfo, reused);

        if (reused) {
            logger().debug("Reusing container; Migration not necessary");
            return;
        }

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(getJdbcUrl());
        dataSource.setUser(getUsername());
        dataSource.setPassword(getPassword());

        try {
            MigrationInitializer.runMigration(dataSource, /* silent */ true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
