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
package org.dependencytrack.dex.activity;

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.config.templating.ConfigTemplateRenderer;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivityExecutor;
import org.dependencytrack.dex.api.annotation.Activity;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.workflow.proto.v1.PublishNotificationArgument;
import org.dependencytrack.notification.NotificationRuleContactsSupplier;
import org.dependencytrack.notification.api.publishing.NotificationPublishContext;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.notification.api.publishing.NotificationPublisherFactory;
import org.dependencytrack.notification.api.publishing.RetryablePublishException;
import org.dependencytrack.notification.api.templating.NotificationTemplate;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.templating.pebble.PebbleNotificationTemplateRendererFactory;
import org.dependencytrack.plugin.NoSuchExtensionException;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.api.filestorage.FileStorage;
import org.dependencytrack.plugin.runtime.config.RuntimeConfigMapper;
import org.dependencytrack.plugin.runtime.config.RuntimeConfigValidationException;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.7.0
 */
@Activity(name = "publish-notification", defaultTaskQueue = "notification")
public final class PublishNotificationActivity implements ActivityExecutor<PublishNotificationArgument, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublishNotificationActivity.class);

    private final PluginManager pluginManager;
    private final RuntimeConfigMapper configMapper;
    private final ConfigTemplateRenderer configTemplateRenderer;
    private final PebbleNotificationTemplateRendererFactory notificationTemplateRendererFactory;

    public PublishNotificationActivity(
            PluginManager pluginManager,
            ConfigTemplateRenderer configTemplateRenderer,
            PebbleNotificationTemplateRendererFactory notificationTemplateRendererFactory) {
        this.pluginManager = pluginManager;
        this.configMapper = RuntimeConfigMapper.getInstance();
        this.configTemplateRenderer = configTemplateRenderer;
        this.notificationTemplateRendererFactory = notificationTemplateRendererFactory;
    }

    @Override
    public @Nullable Void execute(
            ActivityContext ctx,
            @Nullable PublishNotificationArgument argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final Foo foo = getFoo(argument.getRuleId());
        if (foo == null) {
            throw new TerminalApplicationFailureException("Rule does not exist");
        }

        final NotificationPublisherFactory publisherFactory;
        try {
            publisherFactory = pluginManager.getFactory(NotificationPublisher.class, foo.extensionName());
        } catch (NoSuchExtensionException e) {
            throw new TerminalApplicationFailureException(e);
        }

        final Notification notification = getNotification(argument);

        final var template = foo.template() != null
                ? new NotificationTemplate(foo.template(), foo.templateMimeType())
                : null;

        final var publishCtx = new NotificationPublishContext(
                getRuleConfig(publisherFactory.ruleConfigSpec(), foo.publisherConfig()),
                new NotificationRuleContactsSupplier(argument.getRuleId()),
                notificationTemplateRendererFactory.createRenderer(template));

        LOGGER.debug("Publishing notification {}", notification.getId());
        try (final NotificationPublisher publisher = publisherFactory.create()) {
            publisher.publish(publishCtx, notification);
        } catch (Exception e) {
            if (e instanceof RetryablePublishException) {
                throw e;
            }

            throw new TerminalApplicationFailureException(e);
        }

        return null;
    }

    private record Foo(
            String extensionName,
            @Nullable String publisherConfig,
            @Nullable String template,
            @Nullable String templateMimeType) {
    }

    private @Nullable Foo getFoo(long ruleId) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT p."EXTENSION_NAME"
                         , r."PUBLISHER_CONFIG"
                         , p."TEMPLATE"
                         , p."TEMPLATE_MIME_TYPE"
                      FROM "NOTIFICATIONRULE" AS r
                     INNER JOIN "NOTIFICATIONPUBLISHER" AS p
                        ON p."ID" = r."PUBLISHER"
                     WHERE r."ID" = :ruleId
                    """);

            return query
                    .bind("ruleId", ruleId)
                    .map((rs, ctx) -> new Foo(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4)))
                    .findOne()
                    .orElse(null);
        });
    }

    private Notification getNotification(PublishNotificationArgument argument) {
        if (argument.hasNotification()) {
            return argument.getNotification();
        } else if (argument.hasNotificationFileMetadata()) {
            LOGGER.debug("Retrieving notification from file storage");
            try (final var fileStorage = pluginManager.getExtension(FileStorage.class);
                 final InputStream fileInputStream = fileStorage.get(argument.getNotificationFileMetadata())) {
                return Notification.parseFrom(fileInputStream);
            } catch (NoSuchExtensionException e) {
                throw new TerminalApplicationFailureException(e);
            } catch (FileNotFoundException e) {
                throw new TerminalApplicationFailureException("Notification file not found");
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to get notification file", e);
            }
        }

        throw new TerminalApplicationFailureException("No notification found");
    }

    private @Nullable RuntimeConfig getRuleConfig(
            @Nullable RuntimeConfigSpec configSpec,
            @Nullable String configJson) {
        if (configSpec == null) {
            return null;
        }
        if (configJson == null) {
            throw new TerminalApplicationFailureException("No rule configuration provided");
        }

        final JsonNode configJsonNode;
        try {
            configJsonNode = configMapper.validateJson(configJson, configSpec);
        } catch (RuntimeConfigValidationException e) {
            throw new TerminalApplicationFailureException("Rule configuration is invalid", e);
        }

        configTemplateRenderer.renderJson(configJsonNode);

        return configMapper.convert(configJsonNode, configSpec.configClass());
    }

}
