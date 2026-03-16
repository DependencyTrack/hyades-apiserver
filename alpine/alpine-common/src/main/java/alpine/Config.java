/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine;

import alpine.common.config.BuildInfoConfig;
import alpine.common.logging.Logger;
import alpine.common.util.ByteFormat;
import alpine.common.util.PathUtil;
import alpine.common.util.SystemUtil;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.microprofile.config.ConfigProvider;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static alpine.common.config.ConfigUtil.getConfigMapping;
import static java.util.function.Predicate.not;

/**
 * The Config class is responsible for reading the application.properties file.
 *
 * @author Steve Springett
 * @since 1.0.0
 * @deprecated Use {@link org.eclipse.microprofile.config.Config} instead.
 */
@Deprecated(since = "5.7.0")
public class Config {

    private static final Logger LOGGER = Logger.getLogger(Config.class);
    private static final Config INSTANCE;
    private static String systemId;

    static {
        LOGGER.info(StringUtils.repeat("-", 80));
        LOGGER.info("OS Name:      " + SystemUtil.getOsName());
        LOGGER.info("OS Version:   " + SystemUtil.getOsVersion());
        LOGGER.info("OS Arch:      " + SystemUtil.getOsArchitecture());
        LOGGER.info("CPU Cores:    " + SystemUtil.getCpuCores());
        LOGGER.info("Max Memory:   " + new ByteFormat().minimumFractionDigits(1).format2(SystemUtil.getMaxMemory()));
        LOGGER.info("Java Vendor:  " + SystemUtil.getJavaVendor());
        LOGGER.info("Java Version: " + SystemUtil.getJavaVersion());
        LOGGER.info("Java Home:    " + SystemUtil.getJavaHome());
        LOGGER.info("Java Temp:    " + SystemUtil.getJavaTempDir());
        LOGGER.info("User:         " + SystemUtil.getUserName());
        LOGGER.info("User Home:    " + SystemUtil.getUserHome());
        LOGGER.info(StringUtils.repeat("-", 80));
        INSTANCE = new Config();
        INSTANCE.init();
        LOGGER.info(StringUtils.repeat("-", 80));
        LOGGER.info("Application:  " + INSTANCE.getApplicationName());
        LOGGER.info("Version:      " + INSTANCE.getApplicationVersion());
        LOGGER.info("Built-on:     " + INSTANCE.getApplicationBuildTimestamp());
        LOGGER.info(StringUtils.repeat("-", 80));
        LOGGER.info("Framework:    " + INSTANCE.getFrameworkName());
        LOGGER.info("Version :     " + INSTANCE.getFrameworkVersion());
        LOGGER.info("Built-on:     " + INSTANCE.getFrameworkBuildTimestamp());
        LOGGER.info(StringUtils.repeat("-", 80));
    }

    public interface Key {

        /**
         * The name of the property.
         * @return String of the property name
         */
        String getPropertyName();

        /**
         * The default value of the property if not found.
         * @return the default value
         */
        Object getDefaultValue();
    }

    public enum AlpineKey implements Key {
        // @formatter:off
        WORKER_THREADS                         ("dt.worker.threads",             0),
        WORKER_THREAD_MULTIPLIER               ("dt.worker.thread.multiplier",   4),
        DATA_DIRECTORY                         ("dt.data.directory",             "~/.alpine"),
        SECRET_KEY_PATH                        ("dt.secret.key.path",            null),
        DATABASE_URL                           ("dt.database.url",               "jdbc:h2:mem:alpine"),
        DATABASE_USERNAME                      ("dt.database.username",          "sa"),
        DATABASE_PASSWORD                      ("dt.database.password",          ""),
        BCRYPT_ROUNDS                          ("dt.bcrypt.rounds",              14),
        LDAP_ENABLED                           ("dt.ldap.enabled",               false),
        LDAP_SERVER_URL                        ("dt.ldap.server.url",            null),
        LDAP_BASEDN                            ("dt.ldap.basedn",                null),
        LDAP_SECURITY_AUTH                     ("dt.ldap.security.auth",         null),
        LDAP_BIND_USERNAME                     ("dt.ldap.bind.username",         null),
        LDAP_BIND_PASSWORD                     ("dt.ldap.bind.password",         null),
        LDAP_BIND_PASSWORD_FILE                ("dt.ldap.bind.password.file",    null),
        LDAP_AUTH_USERNAME_FMT                 ("dt.ldap.auth.username.format",  null),
        LDAP_ATTRIBUTE_NAME                    ("dt.ldap.attribute.name",        "userPrincipalName"),
        LDAP_ATTRIBUTE_MAIL                    ("dt.ldap.attribute.mail",        "mail"),
        LDAP_GROUPS_FILTER                     ("dt.ldap.groups.filter",         null),
        LDAP_USER_GROUPS_FILTER                ("dt.ldap.user.groups.filter",    null),
        LDAP_GROUPS_SEARCH_FILTER              ("dt.ldap.groups.search.filter",  null),
        LDAP_USERS_SEARCH_FILTER               ("dt.ldap.users.search.filter",   null),
        LDAP_USER_PROVISIONING                 ("dt.ldap.user.provisioning",     false),
        LDAP_TEAM_SYNCHRONIZATION              ("dt.ldap.team.synchronization",  false),
        OIDC_ENABLED                           ("dt.oidc.enabled",               false),
        OIDC_ISSUER                            ("dt.oidc.issuer",                null),
        OIDC_CLIENT_ID                         ("dt.oidc.client.id",             null),
        OIDC_USERNAME_CLAIM                    ("dt.oidc.username.claim",       "sub"),
        OIDC_USER_PROVISIONING                 ("dt.oidc.user.provisioning",    false),
        OIDC_TEAM_SYNCHRONIZATION              ("dt.oidc.team.synchronization", false),
        OIDC_TEAMS_CLAIM                       ("dt.oidc.teams.claim",       "groups"),
        OIDC_TEAMS_DEFAULT                     ("dt.oidc.teams.default",         null),
        OIDC_AUTH_CUSTOMIZER                   ("dt.oidc.auth.customizer",       "alpine.server.auth.DefaultOidcAuthenticationCustomizer"),
        HTTP_PROXY_ADDRESS                     ("dt.http.proxy.address",         null),
        HTTP_PROXY_PORT                        ("dt.http.proxy.port",            null),
        HTTP_PROXY_USERNAME                    ("dt.http.proxy.username",        null),
        HTTP_PROXY_PASSWORD                    ("dt.http.proxy.password",        null),
        HTTP_PROXY_PASSWORD_FILE               ("dt.http.proxy.password.file",   null),
        NO_PROXY                               ("dt.no.proxy",                   null),
        HTTP_TIMEOUT_CONNECTION                ("dt.http.timeout.connection",    30),
        HTTP_TIMEOUT_POOL                      ("dt.http.timeout.pool",          60),
        HTTP_TIMEOUT_SOCKET                    ("dt.http.timeout.socket",        30),
        CORS_ENABLED                           ("dt.cors.enabled",               true),
        CORS_ALLOW_ORIGIN                      ("dt.cors.allow.origin",          "*"),
        CORS_ALLOW_METHODS                     ("dt.cors.allow.methods",         "GET,POST,PUT,PATCH,DELETE,OPTIONS"),
        CORS_ALLOW_HEADERS                     ("dt.cors.allow.headers",         "Origin,Content-Type,Authorization,X-Requested-With,Content-Length,Accept,Origin,X-Api-Key,X-Total-Count,*"),
        CORS_EXPOSE_HEADERS                    ("dt.cors.expose.headers",        "Origin,Content-Type,Authorization,X-Requested-With,Content-Length,Accept,Origin,X-Api-Key,X-Total-Count"),
        CORS_ALLOW_CREDENTIALS                 ("dt.cors.allow.credentials",     true),
        CORS_MAX_AGE                           ("dt.cors.max.age",               3600),
        API_KEY_PREFIX                         ("dt.api.key.prefix",             "alpine_"),
        AUTH_JWT_TTL_SECONDS                   ("dt.auth.jwt.ttl.seconds",       7 * 24 * 60 * 60);
        // @formatter:on

        private String propertyName;
        private Object defaultValue;

        AlpineKey(String item, Object defaultValue) {
            this.propertyName = item;
            this.defaultValue = defaultValue;
        }

        public String getPropertyName() {
            return propertyName;
        }

        public Object getDefaultValue() {
            return defaultValue;
        }
    }

    /**
     * Returns an instance of the Config object.
     * @return a Config object
     * @since 1.0.0
     */
    public static Config getInstance() {
        return INSTANCE;
    }

    /**
     * Initialize the Config object. This method should only be called once.
     */
    void init() {
        LOGGER.info("Initializing Configuration");

        // Force initialization of MicroProfile config.
        org.eclipse.microprofile.config.Config ignored = ConfigProvider.getConfig();

        final File dataDirectory = getDataDirectory();
        if (!dataDirectory.exists()) {
            if (!dataDirectory.mkdirs()) {
                LOGGER.warn("""
                        Data directory %s does not exist, and could not be created. \
                        Please ensure that the user running the JVM has sufficient permissions.\
                        """.formatted(dataDirectory.getAbsolutePath()));
            }
        }
        if (!dataDirectory.canRead()) {
            LOGGER.warn("""
                    Data directory %s is not readable. \
                    Please ensure that the user running the JVM has sufficient permissions.\
                    """.formatted(dataDirectory.getAbsolutePath()));
        }
        if (!dataDirectory.canWrite()) {
            LOGGER.warn("""
                    Data directory %s is not writable. \
                    Please ensure that the user running the JVM has sufficient permissions.\
                    """.formatted(dataDirectory.getAbsolutePath()));
        }

        final File systemIdFile = getSystemIdFilePath();
        if (!systemIdFile.exists()) {
            try (OutputStream fos = Files.newOutputStream(systemIdFile.toPath())) {
                fos.write(UUID.randomUUID().toString().getBytes());
            } catch (IOException e) {
                LOGGER.error("An error occurred writing to " + systemIdFile.getAbsolutePath(), e);
            }
        }
        try {
            systemId = new String(Files.readAllBytes(systemIdFile.toPath()));
        } catch (IOException e) {
            LOGGER.error("Unable to read the contents of " + systemIdFile.getAbsolutePath(), e);
        }
    }

    /**
     * Retrieves the path where the system.id is stored
     * @return a File representing the path to the system.id
     * @since 1.8.0
     */
    private File getSystemIdFilePath() {
        return new File(Config.getInstance().getDataDirectory() + File.separator + "id.system");
    }

    /**
     * Returns the UUID unique to a system deployment.
     * @return the UUID unique to a deployed system
     * @since 1.8.0
     */
    public String getSystemUuid() {
        return systemId;
    }

    /**
     * Returns the Alpine component name.
     * @return the Alpine name
     * @since 1.0.0
     */
    public String getFrameworkName() {
        return getConfigMapping(BuildInfoConfig.class).framework().name();
    }

    /**
     * Returns the Alpine version.
     * @return the Alpine version
     * @since 1.0.0
     */
    public String getFrameworkVersion() {
        return getConfigMapping(BuildInfoConfig.class).framework().version();
    }

    /**
     * Returns the Alpine built timestamp.
     * @return the timestamp in which this version of Alpine was built
     * @since 1.0.0
     */
    public String getFrameworkBuildTimestamp() {
        return getConfigMapping(BuildInfoConfig.class).framework().timestamp();
    }

    /**
     * Returns the Alpine UUID.
     * @return the UUID unique to this build of Alpine
     * @since 1.3.0
     */
    public String getFrameworkBuildUuid() {
        return getConfigMapping(BuildInfoConfig.class).framework().uuid();
    }

    /**
     * Returns the Application component name.
     * @return the Application name
     * @since 1.0.0
     */
    public String getApplicationName() {
        return getConfigMapping(BuildInfoConfig.class).application().name();
    }

    /**
     * Returns the Application version.
     * @return the Application version
     * @since 1.0.0
     */
    public String getApplicationVersion() {
        return getConfigMapping(BuildInfoConfig.class).application().version();
    }

    /**
     * Returns the Application built timestamp.
     * @return the timestamp in which this version of the Application was built
     * @since 1.0.0
     */
    public String getApplicationBuildTimestamp() {
        return getConfigMapping(BuildInfoConfig.class).application().timestamp();
    }

    /**
     * Returns the Application UUID.
     * @return the UUID unique to this build of the application
     * @since 1.3.0
     */
    public String getApplicationBuildUuid() {
        return getConfigMapping(BuildInfoConfig.class).application().uuid();
    }

    /**
     * Returns the fully qualified path to the configured data directory.
     * Expects a fully qualified path or a path starting with ~/
     *
     * Defaults to ~/.alpine if data directory is not specified.
     * @return a File object of the data directory
     * @since 1.0.0
     */
    public File getDataDirectory() {
        final String prop = PathUtil.resolve(getProperty(AlpineKey.DATA_DIRECTORY));
        return new File(prop).getAbsoluteFile();
    }

    /**
     * Return the configured value for the specified Key. As of v1.4.3, this
     * method will first check if the key has been specified as an environment
     * variable. If it has, the method will return the value. If it hasn't
     * been specified in the environment, it will retrieve the value (and optional
     * default value) from the properties configuration.
     *
     * This method is Docker-friendly in that configuration can be specified via
     * environment variables which is a common method of configuration when
     * configuration files are not easily accessible.
     *
     * @param key The Key to return the configuration for
     * @return a String of the value of the configuration
     * @since 1.0.0
     */
    public String getProperty(Key key) {
        return ConfigProvider.getConfig().getOptionalValue(key.getPropertyName(), String.class).orElseGet(
                () -> key.getDefaultValue() != null ? String.valueOf(key.getDefaultValue()) : null);
    }

    /**
     * Check if key with _FILE postfix appended is a defined property name,
     * either in the environment or in the properties configuration. If yes,
     * the named file is read and its content will be the key's value.
     *
     * This method is defined so that passwords can be read from docker secret.
     *
     * @param key The Key to return the configuration for
     * @return a String of the value of the configuration
     * @since 1.7.0
     */
    public String getPropertyOrFile(AlpineKey key) {
        return ConfigProvider.getConfig().getOptionalValue(key.getPropertyName() + ".file", String.class)
                .map(filePath -> {
                    try {
                        return new String(Files.readAllBytes(new File(PathUtil.resolve(filePath)).toPath())).replaceAll("\\s+", "");
                    } catch (IOException e) {
                        LOGGER.error(filePath + " file doesn't exist or not readable.", e);
                        return null;
                    }
                })
                .or(() -> ConfigProvider.getConfig().getOptionalValue(key.getPropertyName(), String.class))
                .orElse(null);
    }

    /**
     * Return the configured value for the specified Key.
     * @param key The Key to return the configuration for
     * @return a int of the value of the configuration
     * @since 1.0.0
     */
    public int getPropertyAsInt(Key key) {
        try {
            return Integer.parseInt(getProperty(key));
        } catch (NumberFormatException e) {
            LOGGER.error("Error parsing number from property: " + key.getPropertyName());
            return -1;
        }
    }

    /**
     * Return the configured value for the specified Key.
     * @param key The Key to return the configuration for
     * @return a long of the value of the configuration
     * @since 1.0.0
     */
    public long getPropertyAsLong(Key key) {
        try {
            return Long.parseLong(getProperty(key));
        } catch (NumberFormatException e) {
            LOGGER.error("Error parsing number from property: " + key.getPropertyName());
            return -1;
        }
    }

    /**
     * Return the configured value for the specified Key.
     * @param key The Key to return the configuration for
     * @return a boolean of the value of the configuration
     * @since 1.0.0
     */
    public boolean getPropertyAsBoolean(Key key) {
        return "true".equalsIgnoreCase(getProperty(key));
    }

    /**
     * Return the configured value for the specified Key.
     * @param key The Key to return the configuration for
     * @return a list of the comma-separated values of the configuration,
     *         or an empty list otherwise
     * @since 2.2.5
     */
    public List<String> getPropertyAsList(Key key) {
        return ConfigProvider.getConfig().getValues(key.getPropertyName(), String.class).stream()
                .map(String::trim)
                .filter(not(String::isEmpty))
                .collect(Collectors.toList());
    }

    /**
     * Determins is unit tests are enabled by checking if the 'alpine.unittests.enabled'
     * system property is set to true or false.
     * @return true if unit tests are enabled, false if not
     * @since 1.0.0
     */
    public static boolean isUnitTestsEnabled() {
        return Boolean.valueOf(System.getProperty("alpine.unittests.enabled", "false"));
    }

    /**
     * Enables unit tests by setting 'alpine.unittests.enabled' system property to true.
     * @since 1.0.0
     */
    public static void enableUnitTests() {
        System.setProperty("alpine.unittests.enabled", "true");
    }

}
