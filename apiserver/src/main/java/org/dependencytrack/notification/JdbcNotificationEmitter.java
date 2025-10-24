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
package org.dependencytrack.notification;

import org.dependencytrack.proto.notification.v1.Notification;
import org.postgresql.util.PGbytea;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.ModelConverter.convert;

/**
 * A {@link NotificationEmitter} that uses the JDBC API for database interactions.
 *
 * @since 5.7.0
 */
abstract class JdbcNotificationEmitter implements NotificationEmitter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final Supplier<Connection> connectionSupplier;

    JdbcNotificationEmitter(final Supplier<Connection> connectionSupplier) {
        this.connectionSupplier = connectionSupplier;
    }

    @Override
    public void emitAll(final Collection<Notification> notifications) {
        requireNonNull(connectionSupplier, "connectionSupplier must not be null");
        emitAll(connectionSupplier.get(), notifications);
    }

    void emitAll(final Connection connection, final Collection<Notification> notifications) {
        final var ids = new ArrayList<String>(notifications.size());
        final var levels = new ArrayList<String>(notifications.size());
        final var scopes = new ArrayList<String>(notifications.size());
        final var groups = new ArrayList<String>(notifications.size());
        final var payloads = new ArrayList<String>(notifications.size());

        for (final Notification notification : notifications) {
            ids.add(notification.getId());
            levels.add(convert(notification.getLevel()).toString());
            scopes.add(convert(notification.getScope()).toString());
            groups.add(convert(notification.getGroup()).toString());
            payloads.add(PGbytea.toPGString(notification.toByteArray()));
        }

        try (final PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO "NOTIFICATION" ("ID", "PAYLOAD")
                SELECT id
                     , CAST(payload AS BYTEA)
                  FROM UNNEST(?, ?, ?, ?, ?)
                    AS t(id, level, scope, "group", payload)
                -- Preliminary check if there even is a rule that could match
                -- the notification. Note that more extensive matching is performed
                -- during dispatch. This is just to avoid unnecessary inserts.
                 WHERE EXISTS(
                         SELECT 1
                           FROM "NOTIFICATIONRULE"
                          WHERE "ENABLED"
                            AND "SCOPE" = t.scope
                            AND "NOTIFICATION_LEVEL" <= t.level
                            AND "NOTIFY_ON" LIKE ('%' || t."group" || '%')
                       )
                """)) {

            ps.setArray(1, connection.createArrayOf("UUID", ids.toArray()));
            ps.setArray(2, connection.createArrayOf("NOTIFICATION_LEVEL", levels.toArray()));
            ps.setArray(3, connection.createArrayOf("TEXT", scopes.toArray()));
            ps.setArray(4, connection.createArrayOf("TEXT", groups.toArray()));
            ps.setArray(5, connection.createArrayOf("BYTEA", payloads.toArray()));

            final int notificationsEmitted = ps.executeUpdate();
            logger.debug("Emitted {}/{} notifications", notificationsEmitted, notifications.size());
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to insert notification records", e);
        }
    }

}
