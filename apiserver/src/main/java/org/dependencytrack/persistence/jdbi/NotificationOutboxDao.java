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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.proto.notification.v1.Notification;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.sqlobject.SqlObject;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;

/**
 * @since 5.7.0
 */
public interface NotificationOutboxDao extends SqlObject {

    default List<Notification> poll(final int limit) {
        final Query query = getHandle().createQuery("""
                WITH polled AS (
                  SELECT "ID"
                    FROM "NOTIFICATION_OUTBOX"
                   ORDER BY "ID"
                   LIMIT :limit
                )
                DELETE
                  FROM "NOTIFICATION_OUTBOX"
                 WHERE "ID" IN (SELECT "ID" FROM polled)
                RETURNING "PAYLOAD"
                """);

        return query
                .bind("limit", limit)
                .mapTo(byte[].class)
                .stream()
                .map(NotificationOutboxDao::deserialize)
                .toList();
    }

    private static Notification deserialize(byte[] data) {
        try {
            return Notification.parseFrom(data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
