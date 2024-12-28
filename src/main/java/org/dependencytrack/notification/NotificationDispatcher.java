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

import org.dependencytrack.parser.dependencytrack.NotificationModelConverter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.notification.v1.Notification;
import org.jdbi.v3.core.Handle;
import org.postgresql.replication.LogSequenceNumber;
import org.postgresql.util.PGbytea;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.PersistenceManager;
import javax.jdo.datastore.JDOConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.SequencedCollection;

public class NotificationDispatcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationDispatcher.class);

    public static void dispatch(final QueryManager qm, final alpine.notification.Notification alpineNotification) {
        dispatch(qm, NotificationModelConverter.convert(alpineNotification));
    }

    public static void dispatch(final QueryManager qm, final Notification notification) {
        final PersistenceManager pm = qm.getPersistenceManager();
        final boolean transactional = pm.currentTransaction().isActive();

        final JDOConnection jdoConnection = pm.getDataStoreConnection();
        final var nativeConnection = (Connection) jdoConnection.getNativeConnection();

        try {
            dispatchAll(nativeConnection, transactional, List.of(notification));
        } finally {
            jdoConnection.close();
        }
    }

    public static void dispatch(final Handle handle, final alpine.notification.Notification alpineNotification) {
        dispatch(handle, NotificationModelConverter.convert(alpineNotification));
    }

    public static void dispatch(final Handle jdbiHandle, final Notification notification) {
        dispatchAll(jdbiHandle.getConnection(), jdbiHandle.isInTransaction(), List.of(notification));
    }

    private static void dispatchAll(
            final Connection connection,
            final boolean transactional,
            final SequencedCollection<Notification> notifications) {
        final var contents = new String[notifications.size()];

        int index = 0;
        for (final Notification notification : notifications) {
            contents[index++] = PGbytea.toPGString(notification.toByteArray());
        }

        // TODO: Use a CTE to check if there even is a rule matching
        //  the notification (high-level)? No point in spamming the WAL
        //  with notifications that won't ever be delivered anyway.
        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT PG_LOGICAL_EMIT_MESSAGE(?, 'notification', "CONTENT")
                  FROM UNNEST(?) AS T("CONTENT")
                """)) {
            ps.setBoolean(1, transactional);
            ps.setArray(2, connection.createArrayOf("BYTEA", contents));
            ps.execute();

            if (LOGGER.isDebugEnabled()) {
                final ResultSet rs = ps.getResultSet();
                while (rs.next()) {
                    final var lsn = LogSequenceNumber.valueOf(rs.getString(1));
                    LOGGER.debug("Dispatched notification to: {}", lsn);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

}
