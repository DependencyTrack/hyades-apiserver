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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.notification.proto.v1.Notification;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.notification.api.TestNotificationFactory.createBomConsumedTestNotification;

public class JdoNotificationEmitterTest extends PersistenceCapableTest {

    private org.dependencytrack.notification.api.emission.NotificationEmitter emitter;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        emitter = new JdoNotificationEmitter(qm, new SimpleMeterRegistry());
    }

    @Test
    public void emitShouldEmitNotification() {
        final Notification notification = createBomConsumedTestNotification();

        emitter.emit(notification);

        assertThat(qm.getNotificationOutbox()).containsOnly(notification);
    }

    @Test
    public void emitAllShouldEmitNotifications() {
        final var notifications = new ArrayList<Notification>(5);

        for (int i = 0; i < 5; i++) {
            notifications.add(createBomConsumedTestNotification());
        }

        emitter.emitAll(notifications);

        assertThat(qm.getNotificationOutbox()).hasSize(5);
    }

    @Test
    public void emitShouldThrowWhenNotificationIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> emitter.emit(null));
    }

    @Test
    public void emitAllShouldThrowWhenNotificationsIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> emitter.emitAll(null));
    }

    @Test
    public void emitShouldThrowWhenNotificationIdIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearId()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

    @Test
    public void emitShouldThrowWhenNotificationScopeIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearScope()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

    @Test
    public void emitShouldThrowWhenNotificationGroupIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearGroup()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

    @Test
    public void emitShouldThrowWhenNotificationLevelIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearLevel()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

    @Test
    public void emitShouldThrowWhenNotificationTimestampIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearTimestamp()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

    @Test
    public void emitShouldThrowWhenNotificationTitleIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearTitle()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

    @Test
    public void emitShouldThrowWhenNotificationContentIsMissing() {
        final Notification notification =
                createBomConsumedTestNotification().toBuilder()
                        .clearContent()
                        .build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> emitter.emit(notification));
    }

}