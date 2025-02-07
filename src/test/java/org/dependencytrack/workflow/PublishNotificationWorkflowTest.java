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
package org.dependencytrack.workflow;

import alpine.notification.NotificationLevel;
import com.google.protobuf.Any;
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.KafkaNotificationPublisher;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Scope;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.proto.workflow.payload.v1alpha1.PublishNotificationActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.PublishNotificationWorkflowArgs;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.util.PersistenceUtil;
import org.dependencytrack.workflow.framework.ScheduleWorkflowRunOptions;
import org.dependencytrack.workflow.framework.WorkflowEngine;
import org.dependencytrack.workflow.framework.WorkflowEngineConfig;
import org.dependencytrack.workflow.framework.WorkflowRunStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.kafka.KafkaContainer;

import javax.sql.DataSource;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.apache.kafka.clients.CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.AUTO_OFFSET_RESET_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.GROUP_ID_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG;
import static org.apache.kafka.clients.consumer.ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

public class PublishNotificationWorkflowTest extends PersistenceCapableTest {

    @Rule
    public KafkaContainer kafkaContainer = new KafkaContainer("apache/kafka-native:3.8.0");

    private WorkflowEngine engine;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        final DataSource dataSource = PersistenceUtil.getDataSource(qm.getPersistenceManager());

        final var config = new WorkflowEngineConfig(UUID.randomUUID(), dataSource);
        config.scheduler().setInitialDelay(Duration.ofMillis(250));
        config.scheduler().setPollInterval(Duration.ofMillis(250));

        engine = new WorkflowEngine(config);
        engine.start();

        engine.registerWorkflowExecutor(
                new PublishNotificationWorkflow(),
                1,
                protoConverter(PublishNotificationWorkflowArgs.class),
                voidConverter(),
                Duration.ofSeconds(5));

        engine.registerActivityExecutor(
                new PublishNotificationActivity(),
                1,
                protoConverter(PublishNotificationActivityArgs.class),
                voidConverter(),
                Duration.ofSeconds(5));
    }

    @After
    @Override
    public void after() {
        if (engine != null) {
            try {
                engine.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        super.after();
    }

    @Test
    public void shouldPublishKafkaNotification() throws Exception {
        try (final var adminClient = AdminClient.create(Map.of(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()))) {
            adminClient.createTopics(List.of(new NewTopic("dtrack-notifications", 1, (short) 1))).all().get();
        }

        final var notificationPublisher = new NotificationPublisher();
        notificationPublisher.setName("Kafka");
        notificationPublisher.setPublisherClass(KafkaNotificationPublisher.class.getName());
        notificationPublisher.setTemplateMimeType("application/protobuf");
        notificationPublisher.setTemplate("n/a");
        qm.persist(notificationPublisher);

        final var notificationRule = new NotificationRule();
        notificationRule.setName("Test");
        notificationRule.setPublisher(notificationPublisher);
        notificationRule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        notificationRule.setScope(NotificationScope.PORTFOLIO);
        notificationRule.setEnabled(true);
        notificationRule.setPublisherConfig(/* language=JSON */ """
                {
                  "destination": "dtrack-notifications",
                  "kafka.producer.bootstrap.servers": "%s",
                  "blocking": "true"
                }
                """.formatted(kafkaContainer.getBootstrapServers()));
        qm.persist(notificationRule);

        final var notification = Notification.newBuilder()
                .setGroup(Group.GROUP_PROJECT_CREATED)
                .setLevel(Level.LEVEL_INFORMATIONAL)
                .setScope(Scope.SCOPE_PORTFOLIO)
                .setTimestamp(Timestamps.now())
                .setSubject(Any.pack(Project.newBuilder()
                        .setUuid("0edf2863-480b-41c7-9cee-1a8129c92a68")
                        .setName("foo")
                        .setVersion("1.0.0")
                        .build()))
                .build();

        final FileMetadata notificationFileMetadata;
        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            notificationFileMetadata = fileStorage.store("notification", notification.toByteArray());
        }

        final UUID workflowRunId = engine.scheduleWorkflowRun(new ScheduleWorkflowRunOptions("publish-notification", 1)
                .withArgument(
                        PublishNotificationWorkflowArgs.newBuilder()
                                .addNotificationRuleNames("Test")
                                .setNotificationFileMetadata(notificationFileMetadata)
                                .build(),
                        protoConverter(PublishNotificationWorkflowArgs.class)));

        await("Workflow run completion")
                .atMost(Duration.ofSeconds(5))
                .until(() -> engine.getRun(workflowRunId), run -> run.status() == WorkflowRunStatus.COMPLETED);

        try (final var consumer = new KafkaConsumer<String, byte[]>(Map.ofEntries(
                Map.entry(BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers()),
                Map.entry(KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName()),
                Map.entry(VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName()),
                Map.entry(GROUP_ID_CONFIG, UUID.randomUUID().toString()),
                Map.entry(AUTO_OFFSET_RESET_CONFIG, "earliest")))) {
            consumer.subscribe(List.of("dtrack-notifications"));

            final ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(1));
            assertThat(records).hasSize(1);

            final ConsumerRecord<String, byte[]> record = records.iterator().next();
            assertThat(record.key()).isEqualTo("0edf2863-480b-41c7-9cee-1a8129c92a68");
            assertThat(record.value()).isEqualTo(notification.toByteArray());
        }
    }

}