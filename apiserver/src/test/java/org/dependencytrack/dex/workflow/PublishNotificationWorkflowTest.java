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
package org.dependencytrack.dex.workflow;

import io.github.resilience4j.core.IntervalFunction;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.config.templating.ConfigTemplateRenderer;
import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.activity.PublishNotificationActivity;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.dex.workflow.proto.v1.PublishNotificationArgument;
import org.dependencytrack.filestorage.memory.MemoryFileStoragePlugin;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationLevel;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.publishing.DefaultNotificationPublisherPlugin;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.filestorage.FileStorage;
import org.dependencytrack.proto.filestorage.v1.FileMetadata;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomConsumedTestNotification;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomProcessedTestNotification;

class PublishNotificationWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(postgresContainer);

    private PluginManager pluginManager;

    @BeforeEach
    void beforeEach() {
        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder().build(),
                new ConfigTemplateRenderer(secretName -> null),
                List.of(FileStorage.class, NotificationPublisher.class));
        pluginManager.loadPlugins(List.of(
                new MemoryFileStoragePlugin(),
                new DefaultNotificationPublisherPlugin()));

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new PublishNotificationWorkflow(),
                protoConverter(PublishNotificationArgument.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerActivity(
                new PublishNotificationActivity(
                        pluginManager,
                        new ConfigTemplateRenderer(secretName -> null),
                        new PebbleNotificationTemplateRendererFactory(Collections.emptyMap())),
                protoConverter(PublishNotificationArgument.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerActivity(
                new DeleteFilesActivity(pluginManager),
                protoConverter(org.dependencytrack.dex.workflow.proto.v1.DeleteFilesArgument.class),
                voidConverter(),
                Duration.ofSeconds(15));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "notification", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-notification", "notification", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void shouldFailWhenRuleDoesNotExist() {
        final var argument = PublishNotificationArgument.newBuilder()
                .setRuleId(123)
                .setRuleName("foo")
                .setNotification(createBomConsumedTestNotification())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                        .withArgument(argument));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("Activity publish-notification failed");
        assertThat(run.failure().getCause().getMessage()).isEqualTo("Rule does not exist");
    }

    @Test
    void shouldFailWhenPublisherExtensionDoesNotExist() {
        final NotificationRule rule = createRule("nonexistent-publisher");

        final var argument = PublishNotificationArgument.newBuilder()
                .setRuleId(rule.getId())
                .setRuleName(rule.getName())
                .setNotification(createBomConsumedTestNotification())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                        .withArgument(argument));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("Activity publish-notification failed");
        assertThat(run.failure().hasCause()).isTrue();
        assertThat(run.failure().getCause().hasCause()).isTrue();
        assertThat(run.failure().getCause().getCause().getMessage())
                .contains("No extension named 'nonexistent-publisher' exists");
    }

    @Test
    void shouldSucceedWhenPublishingNotificationWithInlineNotification() {
        final NotificationRule rule = createRule("console");

        final var argument = PublishNotificationArgument.newBuilder()
                .setRuleId(rule.getId())
                .setRuleName(rule.getName())
                .setNotification(createBomConsumedTestNotification())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                        .withArgument(argument));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
    }

    @Test
    void shouldSucceedWhenPublishingNotificationFromFileStorage() throws Exception {
        final NotificationRule rule = createRule("console");
        final Notification notification = createBomProcessedTestNotification();

        final FileMetadata fileMetadata;
        try (final var fileStorage = pluginManager.getExtension(FileStorage.class)) {
            fileMetadata = fileStorage.store(
                    "notification-%s.bin".formatted(notification.getId()),
                    "application/protobuf",
                    new ByteArrayInputStream(notification.toByteArray()));
        }

        final var argument = PublishNotificationArgument.newBuilder()
                .setRuleId(rule.getId())
                .setRuleName(rule.getName())
                .setNotificationFileMetadata(fileMetadata)
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                        .withArgument(argument));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);

        try (final var fileStorage = pluginManager.getExtension(FileStorage.class)) {
            assertThatExceptionOfType(java.nio.file.NoSuchFileException.class)
                    .isThrownBy(() -> fileStorage.get(fileMetadata));
        }
    }


    @Test
    void shouldFailWhenNoNotificationProvided() {
        final NotificationRule rule = createRule("console");

        final var argument = PublishNotificationArgument.newBuilder()
                .setRuleId(rule.getId())
                .setRuleName(rule.getName())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                        .withArgument(argument));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run).isNotNull();
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).isEqualTo("Activity publish-notification failed");
        assertThat(run.failure().getCause().getMessage()).isEqualTo("No notification found");
    }

    @Test
    void shouldSucceedWithoutDeletingFileWhenNoFileMetadataProvided() {
        final NotificationRule rule = createRule("console");

        final var argument = PublishNotificationArgument.newBuilder()
                .setRuleId(rule.getId())
                .setRuleName(rule.getName())
                .setNotification(createBomConsumedTestNotification())
                .build();

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                        .withArgument(argument));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
    }

    private NotificationRule createRule(String publisherExtensionName) {
        final var publisher = new org.dependencytrack.model.NotificationPublisher();
        publisher.setName("Test Publisher");
        publisher.setExtensionName(publisherExtensionName);
        publisher.setTemplate("{{ notification.subject.project.name }}");
        publisher.setTemplateMimeType("text/plain");
        qm.persist(publisher);

        final var rule = new NotificationRule();
        rule.setName("Test Rule");
        rule.setEnabled(true);
        rule.setScope(NotificationScope.PORTFOLIO);
        rule.setNotificationLevel(NotificationLevel.INFORMATIONAL);
        rule.setNotifyOn(Set.of(NotificationGroup.BOM_CONSUMED));
        rule.setPublisher(publisher);
        return qm.persist(rule);
    }

}