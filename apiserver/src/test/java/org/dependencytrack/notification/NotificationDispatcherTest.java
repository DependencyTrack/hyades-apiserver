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

import alpine.notification.NotificationLevel;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Scope;
import org.junit.Test;

import java.util.LinkedList;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationFactory.newNotificationBuilder;

public class NotificationDispatcherTest extends PersistenceCapableTest {

    @Test
    public void test() {
        final var rule = new NotificationRule();
        rule.setName("foo");
        rule.setNotificationLevel(NotificationLevel.WARNING);
        rule.setScope(NotificationScope.SYSTEM);
        rule.setNotifyOn(Set.of(NotificationGroup.DATASOURCE_MIRRORING));
        rule.setEnabled(true);
        qm.persist(rule);

        new JdoNotificationEmitter(qm).emit(
                newNotificationBuilder()
                        .setLevel(Level.LEVEL_ERROR)
                        .setScope(Scope.SCOPE_SYSTEM)
                        .setGroup(Group.GROUP_DATASOURCE_MIRRORING)
                        .build());

        final var publishTasks = new LinkedList<NotificationPublishTask>();
        new NotificationDispatcher(publishTasks::addAll, 10).run();

        assertThat(publishTasks).hasSize(1);
    }

}