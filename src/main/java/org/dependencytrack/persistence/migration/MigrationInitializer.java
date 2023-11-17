package org.dependencytrack.persistence.migration;

import alpine.Config;
import alpine.common.logging.Logger;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import liquibase.Liquibase;
import liquibase.Scope;
import liquibase.command.CommandScope;
import liquibase.command.core.UpdateCommandStep;
import liquibase.command.core.helpers.DbUrlConnectionCommandStep;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import org.dependencytrack.common.ConfigKey;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.Collections;

public class MigrationInitializer implements ServletContextListener {
    private static final Logger LOGGER = Logger.getLogger(MigrationInitializer.class);

    private final Config config;

    @SuppressWarnings("unused")
    public MigrationInitializer() {
        this(Config.getInstance());
    }

    MigrationInitializer(final Config config) {
        this.config = config;
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getPropertyAsBoolean(ConfigKey.RUN_MIGRATIONS)) {
            LOGGER.info("Migrations are disabled; Skipping");
            return;
        }

        LOGGER.info("Running migrations");
        try (final HikariDataSource dataSource = createDataSource()) {
            Scope.child(Collections.emptyMap(), () -> {
                final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
                final var liquibase = new Liquibase("migration/changelog-main.xml", new ClassLoaderResourceAccessor(), database);

                final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
                updateCommand.addArgumentValue(DbUrlConnectionCommandStep.DATABASE_ARG, liquibase.getDatabase());
                updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
                updateCommand.execute();
            });
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute migrations", e);
        }
    }

    private HikariDataSource createDataSource() {
        final var hikariCfg = new HikariConfig();
        hikariCfg.setJdbcUrl(config.getProperty(Config.AlpineKey.DATABASE_URL));
        hikariCfg.setDriverClassName(config.getProperty(Config.AlpineKey.DATABASE_DRIVER));
        hikariCfg.setUsername(config.getProperty(Config.AlpineKey.DATABASE_USERNAME));
        hikariCfg.setPassword(config.getProperty(Config.AlpineKey.DATABASE_PASSWORD));
        hikariCfg.setMaximumPoolSize(1);
        hikariCfg.setMinimumIdle(1);

        return new HikariDataSource(hikariCfg);
    }
}
