package alpine;

import io.smallrye.config.SmallRyeConfigProviderResolver;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.ConfigValue;
import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RestoreEnvironmentVariables;
import org.junitpioneer.jupiter.RestoreSystemProperties;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import org.junitpioneer.jupiter.SetSystemProperty;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.assertj.core.api.Assertions.assertThat;

public class ConfigTest {

    @AfterAll
    public static void tearDown() {
        releaseCurrentConfig(); // Ensure we're not affecting other tests
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "ALPINE_NO_PROXY", value = "foo, bar, baz")
    void testGetPropertyAsList() {
        releaseCurrentConfig();

        assertThat(Config.getInstance().getPropertyAsList(Config.AlpineKey.NO_PROXY)).containsExactly("foo", "bar", "baz");
    }

    @Test
    void testGetProperty() {
        releaseCurrentConfig();

        // Property with default value.
        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_URL)).isEqualTo("jdbc:h2:mem:alpine");

        // Property without default value.
        assertThat(Config.getInstance().getProperty(Config.AlpineKey.SECRET_KEY_PATH)).isNull();
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "DT_CONFIG_PROFILE", value = "dev")
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_URL", value = "defaultUrl")
    @SetEnvironmentVariable(key = "_DEV_ALPINE_DATABASE_URL", value = "devUrl")
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_USERNAME", value = "defaultUser")
    void testProfiles() {
        releaseCurrentConfig();

        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_URL)).isEqualTo("devUrl");
        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_USERNAME)).isEqualTo("defaultUser");
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_URL", value = "defaultUrl")
    @SetEnvironmentVariable(key = "_PROD_ALPINE_DATABASE_URL", value = "prodUrl")
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_USERNAME", value = "defaultUser")
    void testDefaultProfile() {
        releaseCurrentConfig();

        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_URL)).isEqualTo("defaultUrl");
        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_USERNAME)).isEqualTo("defaultUser");
    }

    @Test
    @RestoreEnvironmentVariables
    @RestoreSystemProperties
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_USERNAME", value = "envUsername")
    @SetSystemProperty(key = "alpine.database.password", value = "propertyPassword")
    void testGetValue() throws Exception {
        final URL propertiesUrl = ConfigTest.class.getResource("/Config_testGetValue.properties");
        assertThat(propertiesUrl).isNotNull();

        final Path tmpPropertiesFile = Files.createTempFile(null, ".properties");
        Files.copy(propertiesUrl.openStream(), tmpPropertiesFile, StandardCopyOption.REPLACE_EXISTING);

        System.setProperty("smallrye.config.locations", tmpPropertiesFile.toUri().toString());

        releaseCurrentConfig();

        ConfigValue configValue = ConfigProvider.getConfig().getConfigValue(Config.AlpineKey.DATABASE_URL.getPropertyName());
        assertThat(configValue.getValue()).isEqualTo("jdbc:h2:mem:alpine");
        assertThat(configValue.getSourceName()).matches(
                "PropertiesConfigSource\\[source=file:.+\\.properties]");

        configValue = ConfigProvider.getConfig().getConfigValue(Config.AlpineKey.DATABASE_USERNAME.getPropertyName());
        assertThat(configValue.getValue()).isEqualTo("envUsername");
        assertThat(configValue.getSourceName()).isEqualTo("EnvConfigSource");

        configValue = ConfigProvider.getConfig().getConfigValue(Config.AlpineKey.DATABASE_PASSWORD.getPropertyName());
        assertThat(configValue.getValue()).isEqualTo("propertyPassword");
        assertThat(configValue.getSourceName()).isEqualTo("SysPropConfigSource");
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_USERNAME", value = "dbUsername")
    @SetEnvironmentVariable(key = "ALPINE_DATABASE_PASSWORD", value = "${alpine.database.username}-123")
    void testExpression() {
        releaseCurrentConfig();

        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_USERNAME)).isEqualTo("dbUsername");
        assertThat(Config.getInstance().getProperty(Config.AlpineKey.DATABASE_PASSWORD)).isEqualTo("dbUsername-123");
    }

    private static void releaseCurrentConfig() {
        final var configProviderResolver = (SmallRyeConfigProviderResolver) ConfigProviderResolver.instance();
        configProviderResolver.releaseConfig(Thread.currentThread().getContextClassLoader());
    }

}