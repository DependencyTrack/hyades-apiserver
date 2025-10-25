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

import com.google.protobuf.DebugFormat;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Scope;
import org.postgresql.util.PGbytea;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_UNSPECIFIED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_UNSPECIFIED;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_UNSPECIFIED;

/**
 * A {@link NotificationEmitter} that uses the JDBC API for database interactions.
 *
 * @since 5.7.0
 */
class JdbcNotificationEmitter implements NotificationEmitter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final Connection connection;
    private final Timer emitLatencyTimer;
    private final MeterProvider<DistributionSummary> emittedDistribution;

    JdbcNotificationEmitter(
            final Connection connection,
            final MeterRegistry meterRegistry) {
        this.connection = connection;
        requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.emitLatencyTimer = Timer
                .builder("dtrack.notifications.emit.latency")
                .register(meterRegistry);
        this.emittedDistribution = DistributionSummary
                .builder("dtrack.notifications.emitted")
                .withRegistry(meterRegistry);

    }

    @Override
    public void emitAll(final Collection<Notification> notifications) {
        emitAll(connection, notifications);
    }

    void emitAll(final Connection connection, final Collection<Notification> notifications) {
        requireNonNull(connection, "connection must not be null");
        requireNonNull(notifications, "notifications must not be null");

        if (notifications.isEmpty()) {
            return;
        }

        final Timer.Sample emitLatencySample = Timer.start();

        final var ids = new ArrayList<String>(notifications.size());
        final var payloads = new ArrayList<String>(notifications.size());

        for (final Notification notification : notifications) {
            requireNonNull(notification, "notification must not be null");

            try {
                validateRequiredFields(notification);
            } catch (final IllegalArgumentException ex) {
                throw new IllegalArgumentException(
                        "Invalid notification: " + DebugFormat.singleLine().toString(notification), ex);
            }

            ids.add(notification.getId());
            payloads.add(PGbytea.toPGString(notification.toByteArray()));
        }

        // TODO: Modify the query such that emission is skipped if
        //  no applicable rule exists. This should be added once the
        //  NotificationDispatcher also performs rule evaluation and routing.
        //  Always inserting all notifications is a temporary solution that
        //  replicates the behavior we previously had with emitting directly to Kafka.

        // INSERT INTO "NOTIFICATION_OUTBOX" ("ID", "PAYLOAD")
        // SELECT id
        //      , payload
        //   FROM UNNEST(?, ?, ?, ?, ?)
        //     AS t(id, level, scope, "group", payload)
        // -- Preliminary check if there even is a rule that could match
        // -- the notification. Note that more extensive matching is performed
        // -- during dispatch. This is just to avoid unnecessary inserts.
        //  WHERE EXISTS(
        //          SELECT 1
        //            FROM "NOTIFICATIONRULE"
        //           WHERE "ENABLED"
        //             AND "SCOPE" = t.scope
        //             AND "NOTIFICATION_LEVEL" <= t.level
        //             AND "NOTIFY_ON" LIKE ('%' || t."group" || '%')
        //        )

        int emittedCount;
        try (final PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO "NOTIFICATION_OUTBOX" ("ID", "PAYLOAD")
                SELECT *
                  FROM UNNEST(?, ?)
                """)) {

            ps.setArray(1, connection.createArrayOf("UUID", ids.toArray()));
            ps.setArray(2, connection.createArrayOf("BYTEA", payloads.toArray()));

            emittedCount = ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to insert notification records", e);
        }

        // TODO: Once emission is filtered based on whether matching rules exist,
        //  this must be modified to only consider actually emitted notifications.
        for (final Notification notification : notifications) {
            emittedDistribution
                    .withTags(List.of(
                            Tag.of("level", convert(notification.getLevel()).name()),
                            Tag.of("scope", convert(notification.getScope()).name()),
                            Tag.of("group", convert(notification.getGroup()).name())))
                    .record(1);
        }

        final long emitLatencyNanos = emitLatencySample.stop(emitLatencyTimer);
        logger.debug(
                "Emitted {} notifications in {}ms",
                emittedCount,
                TimeUnit.NANOSECONDS.toMillis(emitLatencyNanos));
    }

    private static void validateRequiredFields(final Notification notification) {
        if (notification.getId().isEmpty()) {
            throw new IllegalArgumentException("Missing ID");
        }
        if (notification.getScope() == SCOPE_UNSPECIFIED
                || notification.getScope() == Scope.UNRECOGNIZED) {
            throw new IllegalArgumentException("Invalid scope: " + notification.getScope());
        }
        if (notification.getGroup() == GROUP_UNSPECIFIED
                || notification.getGroup() == Group.UNRECOGNIZED) {
            throw new IllegalArgumentException("Invalid group: " + notification.getGroup());
        }
        if (notification.getLevel() == LEVEL_UNSPECIFIED
                || notification.getLevel() == Level.UNRECOGNIZED) {
            throw new IllegalArgumentException("Invalid level: " + notification.getLevel());
        }
        if (!notification.hasTimestamp()) {
            throw new IllegalArgumentException("Missing timestamp");
        }
        if (notification.getTitle().isEmpty()) {
            throw new IllegalArgumentException("Missing title");
        }
        if (notification.getContent().isEmpty()) {
            throw new IllegalArgumentException("Missing content");
        }
    }

}
