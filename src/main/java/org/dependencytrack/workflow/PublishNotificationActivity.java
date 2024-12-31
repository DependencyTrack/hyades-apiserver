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
import org.dependencytrack.workflow.framework.TerminalActivityException;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import java.io.FileNotFoundException;
import java.io.StringReader;
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
            notificationBytes = fileStorage.get(args.getNotificationFileMetadata().getKey());
        } catch (FileNotFoundException e) {
            throw new TerminalActivityException("Notification file does not exist", e);
        }

        final Notification notification;
        try {
            notification = Notification.parseFrom(notificationBytes);
        } catch (InvalidProtocolBufferException e) {
            throw new TerminalActivityException("Failed to parse notification", e);
        }

        final JsonObject publisherConfig = getPublisherConfig(args.getRuleName(), args.getPublisherName());

        // TODO: Lookup and invoke publisher class.
        LOGGER.info(
                "Published notification for rule {} and publisher {} with config {}: {}",
                args.getRuleName(),
                args.getPublisherName(),
                publisherConfig,
                DebugFormat.singleLine().toString(notification));

        return Optional.empty();
    }

    private JsonObject getPublisherConfig(final String ruleName, final String publisherName) {
        final String configJsonStr = withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    WITH
                    "CTE_RULE_PUBLISHER_CONFIG" AS (
                        SELECT CAST("PUBLISHER_CONFIG" AS JSONB) AS "CONFIG"
                          FROM "NOTIFICATIONRULE"
                         WHERE "NAME" = :ruleName
                         LIMIT 1
                    ), "CTE_PUBLISHER_CONFIG" AS (
                        SELECT JSONB_BUILD_OBJECT(
                                 'mimeType', "TEMPLATE_MIME_TYPE"
                               , 'template', "TEMPLATE") AS "CONFIG"
                          FROM "NOTIFICATIONPUBLISHER"
                         WHERE "NAME" = :publisherName
                         LIMIT 1
                    )
                    SELECT (SELECT "CONFIG" FROM "CTE_RULE_PUBLISHER_CONFIG")
                           || (SELECT "CONFIG" FROM "CTE_PUBLISHER_CONFIG")
                    """);

            return query
                    .bind("ruleName", ruleName)
                    .bind("publisherName", publisherName)
                    .mapTo(String.class)
                    .one();
        });

        return Json.createReader(new StringReader(configJsonStr)).readObject();
    }

}
