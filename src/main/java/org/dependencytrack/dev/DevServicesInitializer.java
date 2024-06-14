/*
 * This file is part of Dependency-Track.
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
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.dev;

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.event.kafka.KafkaTopics;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static alpine.Config.AlpineKey.DATABASE_PASSWORD;
import static alpine.Config.AlpineKey.DATABASE_URL;
import static alpine.Config.AlpineKey.DATABASE_USERNAME;
import static org.apache.kafka.clients.admin.AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.common.config.TopicConfig.CLEANUP_POLICY_COMPACT;
import static org.apache.kafka.common.config.TopicConfig.CLEANUP_POLICY_CONFIG;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;

/**
 * @since 5.5.0
 */
public class DevServicesInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(DevServicesInitializer.class);

    // TODO: Consider making these configurable.
    private static final String POSTGRES_IMAGE = "postgres:16-alpine";
    private static final String REDPANDA_IMAGE = "docker.redpanda.com/vectorized/redpanda:v24.1.7";
    private static final String FRONTEND_IMAGE = "ghcr.io/dependencytrack/hyades-frontend:snapshot";

    private AutoCloseable postgresContainer;
    private AutoCloseable redpandaContainer;
    private AutoCloseable frontendContainer;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!"true".equals(System.getProperty("dev.services.enabled"))) {
            return;
        }

        final String postgresJdbcUrl;
        final String postgresUsername;
        final String postgresPassword;
        final String redpandaBootstrapServers;
        final Integer postgresPort;
        final Integer redpandaPort;
        final Integer frontendPort;
        try {
            final Class<?> startablesClass = Class.forName("org.testcontainers.lifecycle.Startables");
            final Method deepStartMethod = startablesClass.getDeclaredMethod("deepStart", Collection.class);

            final Class<?> postgresContainerClass = Class.forName("org.testcontainers.containers.PostgreSQLContainer");
            final Constructor<?> postgresContainerConstructor = postgresContainerClass.getDeclaredConstructor(String.class);
            postgresContainer = (AutoCloseable) postgresContainerConstructor.newInstance(POSTGRES_IMAGE);

            final Class<?> redpandaContainerClass = Class.forName("org.testcontainers.redpanda.RedpandaContainer");
            final Constructor<?> redpandaContainerConstructor = redpandaContainerClass.getDeclaredConstructor(String.class);
            redpandaContainer = (AutoCloseable) redpandaContainerConstructor.newInstance(REDPANDA_IMAGE);

            final Class<?> frontendContainerClass = Class.forName("org.testcontainers.containers.GenericContainer");
            final Constructor<?> frontendContainerConstructor = frontendContainerClass.getDeclaredConstructor(String.class);
            frontendContainer = (AutoCloseable) frontendContainerConstructor.newInstance(FRONTEND_IMAGE);
            frontendContainerClass.getMethod("withEnv", String.class, String.class).invoke(frontendContainer, "API_BASE_URL", "http://localhost:8080");
            frontendContainerClass.getMethod("withExposedPorts", Integer[].class).invoke(frontendContainer, (Object) new Integer[]{8080});

            LOGGER.info("Starting PostgreSQL, Redpanda, and frontend containers");
            final var deepStartFuture = (CompletableFuture<?>) deepStartMethod.invoke(null, List.of(postgresContainer, redpandaContainer, frontendContainer));
            deepStartFuture.join();

            postgresJdbcUrl = (String) postgresContainerClass.getDeclaredMethod("getJdbcUrl").invoke(postgresContainer);
            postgresUsername = (String) postgresContainerClass.getDeclaredMethod("getUsername").invoke(postgresContainer);
            postgresPassword = (String) postgresContainerClass.getDeclaredMethod("getPassword").invoke(postgresContainer);
            redpandaBootstrapServers = (String) redpandaContainerClass.getDeclaredMethod("getBootstrapServers").invoke(redpandaContainer);

            final Class<?> containerStateClass = Class.forName("org.testcontainers.containers.ContainerState");
            postgresPort = (Integer) containerStateClass.getDeclaredMethod("getMappedPort", int.class).invoke(postgresContainer, 5432);
            redpandaPort = (Integer) containerStateClass.getDeclaredMethod("getMappedPort", int.class).invoke(redpandaContainer, 9092);
            frontendPort = (Integer) containerStateClass.getDeclaredMethod("getMappedPort", int.class).invoke(frontendContainer, 8080);
        } catch (Exception e) {
            throw new RuntimeException("Failed to launch containers", e);
        }

        LOGGER.warn("""
                Containers are not auto-discoverable by other services yet. \
                If interaction with other services is required, please use \
                the Docker Compose setup in the DependencyTrack/hyades repository. \
                Auto-discovery is worked on in https://github.com/DependencyTrack/hyades/issues/1188.\
                """);

        final var configOverrides = new Properties();
        configOverrides.put(DATABASE_URL.getPropertyName(), postgresJdbcUrl);
        configOverrides.put(DATABASE_USERNAME.getPropertyName(), postgresUsername);
        configOverrides.put(DATABASE_PASSWORD.getPropertyName(), postgresPassword);
        configOverrides.put(KAFKA_BOOTSTRAP_SERVERS.getPropertyName(), redpandaBootstrapServers);

        try {
            LOGGER.info("Applying config overrides: %s".formatted(configOverrides));
            final Field propertiesField = Config.class.getDeclaredField("properties");
            propertiesField.setAccessible(true);

            final Properties properties = (Properties) propertiesField.get(Config.getInstance());
            properties.putAll(configOverrides);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update configuration", e);
        }

        final var topicsToCreate = new ArrayList<>(List.of(
                new NewTopic(KafkaTopics.NEW_EPSS.name(), 1, (short) 1).configs(Map.of(CLEANUP_POLICY_CONFIG, CLEANUP_POLICY_COMPACT)),
                new NewTopic(KafkaTopics.NEW_VULNERABILITY.name(), 1, (short) 1).configs(Map.of(CLEANUP_POLICY_CONFIG, CLEANUP_POLICY_COMPACT)),
                new NewTopic(KafkaTopics.NOTIFICATION_ANALYZER.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_BOM.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_CONFIGURATION.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_DATASOURCE_MIRRORING.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_FILE_SYSTEM.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_INTEGRATION.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_NEW_VULNERABILITY.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_NEW_VULNERABLE_DEPENDENCY.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_POLICY_VIOLATION.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_PROJECT_AUDIT_CHANGE.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_REPOSITORY.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.NOTIFICATION_VEX.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.REPO_META_ANALYSIS_RESULT.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.VULN_ANALYSIS_COMMAND.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.VULN_ANALYSIS_RESULT.name(), 1, (short) 1),
                new NewTopic(KafkaTopics.VULN_ANALYSIS_RESULT_PROCESSED.name(), 1, (short) 1)
        ));

        try (final var adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, redpandaBootstrapServers))) {
            LOGGER.info("Creating topics: %s".formatted(topicsToCreate));
            adminClient.createTopics(topicsToCreate).all().get();
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException("Failed to create topics", e);
        }

        LOGGER.info("PostgreSQL is listening at localhost:%d".formatted(postgresPort));
        LOGGER.info("Redpanda is listening at localhost:%d".formatted(redpandaPort));
        LOGGER.info("Frontend is listening at http://localhost:%d".formatted(frontendPort));
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (postgresContainer != null) {
            LOGGER.info("Stopping postgres container");
            try {
                postgresContainer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to stop PostgreSQL container", e);
            }
        }
        if (redpandaContainer != null) {
            LOGGER.info("Stopping redpanda container");
            try {
                redpandaContainer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to stop Redpanda container", e);
            }
        }
        if (frontendContainer != null) {
            LOGGER.info("Stopping frontend container");
            try {
                frontendContainer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to stop frontend container", e);
            }
        }
    }

}
