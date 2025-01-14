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

import com.google.protobuf.DebugFormat;
import com.google.protobuf.InvalidProtocolBufferException;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.workflow.payload.v1alpha1.PublishNotificationActivityArgs;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityRunContext;
import org.dependencytrack.workflow.framework.ActivityRunner;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.StatementContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import java.io.FileNotFoundException;
import java.io.StringReader;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@Activity(name = "publish-notification")
public class PublishNotificationActivity implements ActivityRunner<PublishNotificationActivityArgs, Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PublishNotificationActivity.class);

    @Override
    public Optional<Void> run(final ActivityRunContext<PublishNotificationActivityArgs> ctx) throws Exception {
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

        // TODO: Lookup and invoke publisher class.
        LOGGER.info(
                "Published notification with context {}: {}",
                publishContext,
                DebugFormat.singleLine().toString(notification));

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
