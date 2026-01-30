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
import java.util.Map;

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
    public void testGetPassThroughPropertiesEmpty() {
        releaseCurrentConfig();

        assertThat(Config.getInstance().getPassThroughProperties("datanucleus")).isEmpty();
    }

    @Test
    @RestoreEnvironmentVariables
    @RestoreSystemProperties
    @SetEnvironmentVariable(key = "ALPINE_FOO", value = "fromEnv1")
    @SetEnvironmentVariable(key = "ALPINE_DATANUCLEUS", value = "fromEnv2")
    @SetEnvironmentVariable(key = "ALPINE_DATANUCLEUS_FOO", value = "fromEnv3")
    @SetEnvironmentVariable(key = "ALPINE_DATANUCLEUS_FOO_BAR", value = "fromEnv4")
    @SetEnvironmentVariable(key = "ALPINE_DATA_NUCLEUS_FOO", value = "fromEnv5")
    @SetEnvironmentVariable(key = "DATANUCLEUS_FOO", value = "fromEnv6")
    @SetEnvironmentVariable(key = "ALPINE_DATANUCLEUS_FROM_ENV", value = "fromEnv7")
    @SetEnvironmentVariable(key = "alpine_datanucleus_from_env_lowercase", value = "fromEnv8")
    @SetEnvironmentVariable(key = "Alpine_DataNucleus_From_Env_MixedCase", value = "fromEnv9")
    @SetEnvironmentVariable(key = "ALPINE_DATANUCLEUS_EXPRESSION_FROM_ENV", value = "${alpine.datanucleus.from.env}")
    public void testGetPassThroughProperties() {
        final URL propertiesUrl = ConfigTest.class.getResource("/Config_testGetPassThroughProperties.properties");
        assertThat(propertiesUrl).isNotNull();

        System.setProperty("smallrye.config.locations", propertiesUrl.getPath());

        releaseCurrentConfig();

        assertThat(Config.getInstance().getPassThroughProperties("datanucleus"))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "datanucleus.foo", "fromProps3", // Properties take precedence because config location was set via system properties.
                        "datanucleus.foo.bar", "fromProps4", // Properties take precedence because config location was set via system properties.
                        "datanucleus.from.env", "fromEnv7",
                        "datanucleus.from.props", "fromProps7",
                        "datanucleus.from.env.lowercase", "fromEnv8",
                        "datanucleus.from.env.mixedcase", "fromEnv9",
                        "datanucleus.expression.from.props", "fromProps3",
                        "datanucleus.expression.from.env", "fromEnv7"
                ));
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "SMALLRYE_CONFIG_PROFILE", value = "dev")
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