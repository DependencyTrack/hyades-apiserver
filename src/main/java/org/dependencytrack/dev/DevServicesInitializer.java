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
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.dependencytrack.event.kafka.KafkaTopics;

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
import static org.dependencytrack.common.ConfigKey.DEV_SERVICES_ENABLED;
import static org.dependencytrack.common.ConfigKey.DEV_SERVICES_IMAGE_FRONTEND;
import static org.dependencytrack.common.ConfigKey.DEV_SERVICES_IMAGE_KAFKA;
import static org.dependencytrack.common.ConfigKey.DEV_SERVICES_IMAGE_POSTGRES;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;

/**
 * @since 5.5.0
 */
public class DevServicesInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(DevServicesInitializer.class);

    private AutoCloseable postgresContainer;
    private AutoCloseable kafkaContainer;
    private AutoCloseable frontendContainer;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!"true".equals(getProperty(DEV_SERVICES_ENABLED))) {
            return;
        }

        try {
            // Testcontainers will not be available outside the test scope,
            // except when running via the dev-services Maven profile.
            Class.forName("org.testcontainers.Testcontainers");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Dev services are not available for production builds");
        }

        final String postgresJdbcUrl;
        final String postgresUsername;
        final String postgresPassword;
        final String kafkaBootstrapServers;
        final Integer postgresPort;
        final Integer kafkaPort;
        final Integer frontendPort;
        try {
            final Class<?> startablesClass = Class.forName("org.testcontainers.lifecycle.Startables");
            final Method deepStartMethod = startablesClass.getDeclaredMethod("deepStart", Collection.class);

            final Class<?> imagePullPolicyClass = Class.forName("org.testcontainers.images.ImagePullPolicy");
            final Class<?> pullPolicyClass = Class.forName("org.testcontainers.images.PullPolicy");
            final Object alwaysPullPolicy = pullPolicyClass.getDeclaredMethod("alwaysPull").invoke(null);

            final Class<?> postgresContainerClass = Class.forName("org.testcontainers.containers.PostgreSQLContainer");
            final Constructor<?> postgresContainerConstructor = postgresContainerClass.getDeclaredConstructor(String.class);
            postgresContainer = (AutoCloseable) postgresContainerConstructor.newInstance(getProperty(DEV_SERVICES_IMAGE_POSTGRES));
            postgresContainerClass.getMethod("withUrlParam", String.class, String.class).invoke(postgresContainer, "reWriteBatchedInserts", "true");

            // TODO: Detect when Apache Kafka is requested vs. when Kafka is requested,
            //   and pick the corresponding Testcontainers class accordingly.
            final Class<?> kafkaContainerClass = Class.forName("org.testcontainers.kafka.KafkaContainer");
            final Constructor<?> kafkaContainerConstructor = kafkaContainerClass.getDeclaredConstructor(String.class);
            kafkaContainer = (AutoCloseable) kafkaContainerConstructor.newInstance(getProperty(DEV_SERVICES_IMAGE_KAFKA));
            // TODO: Remove this when Kafka >= 3.9.1 is available.
            //   * https://github.com/testcontainers/testcontainers-java/issues/9506#issuecomment-2463504967
            //   * https://issues.apache.org/jira/browse/KAFKA-18281
            kafkaContainerClass.getMethod("withEnv", String.class, String.class).invoke(kafkaContainer, "KAFKA_LISTENERS", "PLAINTEXT://:9092,BROKER://:9093,CONTROLLER://:9094");

            final Class<?> frontendContainerClass = Class.forName("org.testcontainers.containers.GenericContainer");
            final Constructor<?> frontendContainerConstructor = frontendContainerClass.getDeclaredConstructor(String.class);
            frontendContainer = (AutoCloseable) frontendContainerConstructor.newInstance(getProperty(DEV_SERVICES_IMAGE_FRONTEND));
            frontendContainerClass.getMethod("withEnv", String.class, String.class).invoke(frontendContainer, "API_BASE_URL", "http://localhost:8080");
            frontendContainerClass.getMethod("withExposedPorts", Integer[].class).invoke(frontendContainer, (Object) new Integer[]{8080});
            if (Config.getInstance().getProperty(DEV_SERVICES_IMAGE_FRONTEND).endsWith(":snapshot")) {
                frontendContainerClass.getMethod("withImagePullPolicy", imagePullPolicyClass).invoke(frontendContainer, alwaysPullPolicy);
            }

            LOGGER.info("Starting PostgreSQL, Kafka, and frontend containers");
            final var deepStartFuture = (CompletableFuture<?>) deepStartMethod.invoke(null, List.of(postgresContainer, kafkaContainer, frontendContainer));
            deepStartFuture.join();

            postgresJdbcUrl = (String) postgresContainerClass.getDeclaredMethod("getJdbcUrl").invoke(postgresContainer);
            postgresUsername = (String) postgresContainerClass.getDeclaredMethod("getUsername").invoke(postgresContainer);
            postgresPassword = (String) postgresContainerClass.getDeclaredMethod("getPassword").invoke(postgresContainer);
            kafkaBootstrapServers = (String) kafkaContainerClass.getDeclaredMethod("getBootstrapServers").invoke(kafkaContainer);

            final Class<?> containerStateClass = Class.forName("org.testcontainers.containers.ContainerState");
            postgresPort = (Integer) containerStateClass.getDeclaredMethod("getMappedPort", int.class).invoke(postgresContainer, 5432);
            kafkaPort = (Integer) containerStateClass.getDeclaredMethod("getMappedPort", int.class).invoke(kafkaContainer, 9092);
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
        configOverrides.put(KAFKA_BOOTSTRAP_SERVERS.getPropertyName(), kafkaBootstrapServers);

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

        try (final var adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaBootstrapServers))) {
            LOGGER.info("Creating topics: %s".formatted(topicsToCreate));
            adminClient.createTopics(topicsToCreate).all().get();
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException("Failed to create topics", e);
        }

        LOGGER.info("PostgreSQL is listening at localhost:%d".formatted(postgresPort));
        LOGGER.info("Kafka is listening at localhost:%d".formatted(kafkaPort));
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
        if (kafkaContainer != null) {
            LOGGER.info("Stopping Kafka container");
            try {
                kafkaContainer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to stop Kafka container", e);
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

    private static String getProperty(final Config.Key configKey) {
        // Allow configs to be set via system properties, and fall
        // back to the usual Config mechanism otherwise.
        // Since setting environment variables via Maven profiles is
        // not possible, system properties provide a better UX over
        // manually editing application.properties, or manually setting
        // environment variables.
        return System.getProperty(
                configKey.getPropertyName(),
                Config.getInstance().getProperty(configKey)
        );
    }

}
