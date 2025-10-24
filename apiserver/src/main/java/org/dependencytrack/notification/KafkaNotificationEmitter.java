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

import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.proto.notification.v1.Notification;

import java.util.Collection;

/**
 * A {@link NotificationEmitter} based on Kafka.
 * <p>
 * This implementation does <strong>not</strong> support atomic emission
 * and should be used outside of database transactions.
 * <p>
 * This class is temporarily used as adapter for the new notification emission
 * and dispatching system. It will be replaced with database-backed implementations
 * once the system has been fully migrated.
 *
 * @since 5.7.0
 */
public final class KafkaNotificationEmitter implements NotificationEmitter {

    private final KafkaEventDispatcher eventDispatcher;

    public KafkaNotificationEmitter(final KafkaEventDispatcher eventDispatcher) {
        this.eventDispatcher = eventDispatcher;
    }

    public KafkaNotificationEmitter() {
        this(new KafkaEventDispatcher());
    }

    @Override
    public void emitAll(final Collection<Notification> notifications) {
        eventDispatcher.dispatchAllNotificationProtos(notifications);
    }

}
