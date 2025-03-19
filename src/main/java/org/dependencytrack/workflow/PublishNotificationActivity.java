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

import com.google.protobuf.InvalidProtocolBufferException;
import org.dependencytrack.notification.publisher.NotificationPublisher;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityClient;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.dependencytrack.workflow.payload.proto.v1alpha1.PublishNotificationActivityArgs;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.StatementContext;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import java.io.FileNotFoundException;
import java.io.StringReader;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Activity(name = "publish-notification")
public class PublishNotificationActivity implements ActivityExecutor<PublishNotificationActivityArgs, Void> {

    public static final ActivityClient<PublishNotificationActivityArgs, Void> CLIENT =
            ActivityClient.of(
                    PublishNotificationActivity.class,
                    protoConverter(PublishNotificationActivityArgs.class),
                    voidConverter());

    private final List<NotificationPublisher> publishers;

    PublishNotificationActivity(final List<NotificationPublisher> publishers) {
        this.publishers = publishers;
    }

    public PublishNotificationActivity() {
        this(ServiceLoader.load(NotificationPublisher.class).stream()
                .map(ServiceLoader.Provider::get)
                .sorted(Comparator.comparing(publisher -> publisher.getClass().getName()))
                .toList());
    }

    @Override
    public Optional<Void> execute(final ActivityContext<PublishNotificationActivityArgs> ctx) throws Exception {
        final PublishNotificationActivityArgs args = ctx.argument().orElseThrow();

        final byte[] notificationBytes;
        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            notificationBytes = fileStorage.get(args.getNotificationFileMetadata());
        } catch (FileNotFoundException e) {
            throw new ApplicationFailureException("Notification file does not exist", e, true);
        }

        final Notification notification;
        try {
            notification = Notification.parseFrom(notificationBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new ApplicationFailureException("Failed to parse notification", e, true);
        }

        final PublishContext publishContext = getPublishContext(args.getNotificationRuleName());

        final NotificationPublisher publisher = publishers.stream()
                .filter(candidate -> candidate.getClass().getName().equals(publishContext.publisherClass()))
                .findAny()
                .orElseThrow(() -> new ApplicationFailureException(
                        "No publisher of type %s found".formatted(publishContext.publisherClass()), null, true));

        final var publisherContext = new NotificationPublisher.Context(
                publishContext.ruleName(),
                publishContext.publisherName(),
                publishContext.template(),
                publishContext.templateMimeType(),
                publishContext.publisherConfig());
        publisher.publish(publisherContext, notification);

        return Optional.empty();
    }

    private record PublishContext(
            String ruleName,
            String publisherName,
            String publisherClass,
            String template,
            String templateMimeType,
            JsonObject publisherConfig) {
    }

    private static final class PublishContextRowMapper implements RowMapper<PublishContext> {

        @Override
        public PublishContext map(final ResultSet rs, final StatementContext ctx) throws SQLException {
            JsonObject publisherConfig = null;
            final String publisherConfigJson = rs.getString("PUBLISHER_CONFIG");
            if (!rs.wasNull()) {
                publisherConfig = Json.createReader(new StringReader(publisherConfigJson)).readObject();
            }

            return new PublishContext(
                    rs.getString("RULE_NAME"),
                    rs.getString("PUBLISHER_NAME"),
                    rs.getString("PUBLISHER_CLASS"),
                    rs.getString("TEMPLATE"),
                    rs.getString("TEMPLATE_MIME_TYPE"),
                    publisherConfig);
        }

    }

    private PublishContext getPublishContext(final String ruleName) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "NOTIFICATIONRULE"."NAME" AS "RULE_NAME"
                         , "NOTIFICATIONPUBLISHER"."NAME" AS "PUBLISHER_NAME"
                         , "NOTIFICATIONPUBLISHER"."PUBLISHER_CLASS"
                         , "NOTIFICATIONPUBLISHER"."TEMPLATE"
                         , "NOTIFICATIONPUBLISHER"."TEMPLATE_MIME_TYPE"
                         , "NOTIFICATIONRULE"."PUBLISHER_CONFIG"
                      FROM "NOTIFICATIONRULE"
                     INNER JOIN "NOTIFICATIONPUBLISHER"
                        ON "NOTIFICATIONPUBLISHER"."ID" = "NOTIFICATIONRULE"."PUBLISHER"
                     WHERE "NOTIFICATIONRULE"."NAME" = :ruleName
                    """);

            return query
                    .bind("ruleName", ruleName)
                    .map(new PublishContextRowMapper())
                    .one();
        });
    }

}
