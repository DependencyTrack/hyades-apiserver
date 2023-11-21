package org.dependencytrack.persistence.migration.change.v530;

import liquibase.Liquibase;
import liquibase.Scope;
import liquibase.command.CommandScope;
import liquibase.command.core.UpdateCommandStep;
import liquibase.command.core.helpers.DbUrlConnectionCommandStep;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.migration.change.v530.RenameNumberedIndexesChange.getIndexNameMappingsFromPostgres;

public class RenameNumberedIndexesChangeTest {

    private PostgreSQLContainer<?> postgresContainer;

    @Before
    @SuppressWarnings("resource")
    public void setUp() {
        postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                .withInitScript("migration/custom/schema-v5.2.0-postgresql.sql");
        postgresContainer.start();
    }

    @After
    public void tearDown() {
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void test() throws Exception {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        Scope.child(Collections.emptyMap(), () -> {
            final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
            final var liquibase = new Liquibase("migration/custom/RenameNumberedIndexesChangeTest-changelog.xml", new ClassLoaderResourceAccessor(), database);

            final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
            updateCommand.addArgumentValue(DbUrlConnectionCommandStep.DATABASE_ARG, liquibase.getDatabase());
            updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
            updateCommand.execute();
        });

        assertThat(getIndexNameMappingsFromPostgres(new JdbcConnection(dataSource.getConnection()))).isEmpty();
    }
}