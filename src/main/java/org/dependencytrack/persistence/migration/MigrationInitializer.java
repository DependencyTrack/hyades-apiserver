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
import liquibase.logging.core.NoOpLogService;
import liquibase.resource.ClassLoaderResourceAccessor;
import org.dependencytrack.common.ConfigKey;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Optional;

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
            runMigration(dataSource, false);
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute migrations", e);
        }
    }

    public static void runMigration(final DataSource dataSource, final boolean silent) throws Exception {
        final var scopeAttributes = new HashMap<String, Object>();
        if (silent) {
            scopeAttributes.put(Scope.Attr.logService.name(), new NoOpLogService());
        }

        Scope.child(scopeAttributes, () -> {
            final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
            final var liquibase = new Liquibase("migration/changelog-main.xml", new ClassLoaderResourceAccessor(), database);

            final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
            updateCommand.addArgumentValue(DbUrlConnectionCommandStep.DATABASE_ARG, liquibase.getDatabase());
            updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
            updateCommand.execute();
        });
    }

    private HikariDataSource createDataSource() {
        final String jdbcUrl = Optional.ofNullable(config.getProperty(ConfigKey.DATABASE_MIGRATION_URL))
                .orElseGet(() -> config.getProperty(Config.AlpineKey.DATABASE_URL));
        final String username = Optional.ofNullable(config.getProperty(ConfigKey.DATABASE_MIGRATION_USERNAME))
                .orElseGet(() -> config.getProperty(Config.AlpineKey.DATABASE_USERNAME));
        final String password = Optional.ofNullable(config.getProperty(ConfigKey.DATABASE_MIGRATION_PASSWORD))
                .orElseGet(() -> config.getProperty(Config.AlpineKey.DATABASE_PASSWORD));

        final var hikariCfg = new HikariConfig();
        hikariCfg.setJdbcUrl(jdbcUrl);
        hikariCfg.setDriverClassName(config.getProperty(Config.AlpineKey.DATABASE_DRIVER));
        hikariCfg.setUsername(username);
        hikariCfg.setPassword(password);
        hikariCfg.setMaximumPoolSize(1);
        hikariCfg.setMinimumIdle(1);

        return new HikariDataSource(hikariCfg);
    }
}
