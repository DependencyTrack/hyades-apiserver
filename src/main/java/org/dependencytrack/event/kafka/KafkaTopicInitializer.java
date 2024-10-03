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
package org.dependencytrack.event.kafka;

import alpine.Config;
import alpine.common.logging.Logger;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.CreateTopicsOptions;
import org.apache.kafka.clients.admin.CreateTopicsResult;
import org.apache.kafka.clients.admin.DescribeTopicsOptions;
import org.apache.kafka.clients.admin.DescribeTopicsResult;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.errors.UnknownTopicOrPartitionException;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.CommonClientConfigs.CLIENT_ID_CONFIG;
import static org.dependencytrack.common.ConfigKey.INIT_TASKS_ENABLED;
import static org.dependencytrack.common.ConfigKey.INIT_TASKS_KAFKA_TOPICS_ENABLED;
import static org.dependencytrack.common.ConfigKey.KAFKA_BOOTSTRAP_SERVERS;

/**
 * @since 5.6.0
 */
public class KafkaTopicInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaTopicInitializer.class);

    private final Config config = Config.getInstance();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!config.getPropertyAsBoolean(INIT_TASKS_ENABLED)) {
            LOGGER.debug("Not initializing Kafka topics because %s is disabled"
                    .formatted(INIT_TASKS_ENABLED.getPropertyName()));
            return;
        }
        if (!config.getPropertyAsBoolean(INIT_TASKS_KAFKA_TOPICS_ENABLED)) {
            LOGGER.debug("Not initializing Kafka topics because %s is disabled"
                    .formatted(INIT_TASKS_KAFKA_TOPICS_ENABLED.getPropertyName()));
            return;
        }

        LOGGER.warn("Auto-creating topics with default configuration is not recommended for production deployments");

        try (final AdminClient adminClient = createAdminClient()) {
            final List<KafkaTopics.Topic<?, ?>> topicsToCreate = determineTopicsToCreate(adminClient);
            if (topicsToCreate.isEmpty()) {
                LOGGER.info("All topics exist already; Nothing to do");
                return;
            }

            createTopics(adminClient, topicsToCreate);
            LOGGER.info("Successfully created %d topics".formatted(topicsToCreate.size()));
        }
    }

    private List<KafkaTopics.Topic<?, ?>> determineTopicsToCreate(final AdminClient adminClient) {
        final Map<String, KafkaTopics.Topic<?, ?>> topicByName = KafkaTopics.ALL_TOPICS.stream()
                .collect(Collectors.toMap(KafkaTopics.Topic::name, Function.identity()));

        final var topicsToCreate = new ArrayList<KafkaTopics.Topic<?, ?>>(topicByName.size());

        final var describeTopicsOptions = new DescribeTopicsOptions().timeoutMs(3_000);
        final DescribeTopicsResult topicsResult = adminClient.describeTopics(topicByName.keySet(), describeTopicsOptions);

        final var exceptionsByTopicName = new HashMap<String, Throwable>();
        for (final Map.Entry<String, KafkaFuture<TopicDescription>> entry : topicsResult.topicNameValues().entrySet()) {
            final String topicName = entry.getKey();
            try {
                entry.getValue().get();
            } catch (ExecutionException e) {
                if (e.getCause() instanceof UnknownTopicOrPartitionException) {
                    LOGGER.debug("Topic %s does not exist and will need to be created".formatted(topicName));
                    topicsToCreate.add(topicByName.get(topicName));
                } else {
                    exceptionsByTopicName.put(topicName, e.getCause());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("""
                        Thread was interrupted while waiting for broker response. \
                        The existence of topic %s can not be determined.""".formatted(topicName), e);
            }
        }

        if (!exceptionsByTopicName.isEmpty()) {
            final String exceptionSummary = exceptionsByTopicName.entrySet().stream()
                    .map(entry -> "{topic=%s, error=%s}".formatted(entry.getKey(), entry.getValue()))
                    .collect(Collectors.joining(", ", "[", "]"));
            throw new IllegalStateException("Existence of %d topic(s) could not be verified: %s"
                    .formatted(exceptionsByTopicName.size(), exceptionSummary));
        }

        return topicsToCreate;
    }

    private void createTopics(final AdminClient adminClient, final Collection<KafkaTopics.Topic<?, ?>> topics) {
        final List<NewTopic> newTopics = topics.stream()
                .map(topic -> {
                    final var newTopic = new NewTopic(
                            topic.name(),
                            topic.defaultConfig().partitions(),
                            topic.defaultConfig().replicationFactor());
                    if (topic.defaultConfig().configs() != null) {
                        return newTopic.configs(topic.defaultConfig().configs());
                    }

                    return newTopic;
                })
                .toList();

        final var createTopicsOptions = new CreateTopicsOptions().timeoutMs(3_000);
        final CreateTopicsResult createTopicsResult = adminClient.createTopics(newTopics, createTopicsOptions);

        final var exceptionsByTopicName = new HashMap<String, Throwable>();
        for (final Map.Entry<String, KafkaFuture<Void>> entry : createTopicsResult.values().entrySet()) {
            final String topicName = entry.getKey();
            try {
                entry.getValue().get();
            } catch (ExecutionException e) {
                exceptionsByTopicName.put(topicName, e.getCause());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("""
                        Thread was interrupted while waiting for broker response. \
                        Successful creation of topic %s can not be verified.""".formatted(topicName), e);
            }
        }

        if (!exceptionsByTopicName.isEmpty()) {
            final String exceptionSummary = exceptionsByTopicName.entrySet().stream()
                    .map(entry -> "{topic=%s, error=%s}".formatted(entry.getKey(), entry.getValue()))
                    .collect(Collectors.joining(", ", "[", "]"));
            throw new IllegalStateException("Failed to create %d topic(s): %s"
                    .formatted(exceptionsByTopicName.size(), exceptionSummary));
        }
    }

    private AdminClient createAdminClient() {
        final var adminClientConfig = new HashMap<String, Object>();
        adminClientConfig.put(BOOTSTRAP_SERVERS_CONFIG, config.getProperty(KAFKA_BOOTSTRAP_SERVERS));
        adminClientConfig.put(CLIENT_ID_CONFIG, "%s-admin-client".formatted("instanceId"));

        LOGGER.debug("Creating admin client with options %s".formatted(adminClientConfig));
        return AdminClient.create(adminClientConfig);
    }

}
