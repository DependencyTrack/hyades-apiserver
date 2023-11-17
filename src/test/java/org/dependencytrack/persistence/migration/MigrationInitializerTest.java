package org.dependencytrack.persistence.migration;

import alpine.Config;
import org.h2.Driver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        MigrationInitializerTest.H2Test.class,
        MigrationInitializerTest.PostgreSqlTest.class,
})
public class MigrationInitializerTest {

    public static class H2Test {

        @Test
        public void test() {
            final Config configMock = createConfigMock("jdbc:h2:mem:", Driver.class.getName(), "sa", "");
            new MigrationInitializer(configMock).contextInitialized(null);
        }

    }

    public static class PostgreSqlTest {

        private PostgreSQLContainer<?> postgresContainer;

        @Before
        public void setUp() {
            postgresContainer = new PostgreSQLContainer<>(DockerImageName.parse("postgres:11-alpine"));
            postgresContainer.start();
        }

        @After
        public void tearDown() {
            if (postgresContainer != null) {
                postgresContainer.stop();
            }
        }

        @Test
        public void test() {
            final Config configMock = createConfigMock(postgresContainer.getJdbcUrl(),
                    postgresContainer.getDriverClassName(),
                    postgresContainer.getUsername(),
                    postgresContainer.getPassword());
            new MigrationInitializer(configMock).contextInitialized(null);
        }

    }

    private static Config createConfigMock(final String jdbcUrl, final String driverClassName,
                                           final String username, final String password) {
        final var configMock = mock(Config.class);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_URL))).thenReturn(jdbcUrl);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_DRIVER))).thenReturn(driverClassName);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_USERNAME))).thenReturn(username);
        when(configMock.getProperty(eq(Config.AlpineKey.DATABASE_PASSWORD))).thenReturn(password);
        return configMock;
    }
}
