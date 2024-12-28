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

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Scope;
import org.junit.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.postgresql.jdbc.PreferQueryMode;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.awaitility.Awaitility.await;

public class NotificationRouterTest extends PersistenceCapableTest {

    @Test
    public void test() throws Exception {
        final var replicationDataSource = new PGSimpleDataSource();
        replicationDataSource.setUrl(postgresContainer.getJdbcUrl());
        replicationDataSource.setUser(postgresContainer.getUsername());
        replicationDataSource.setPassword(postgresContainer.getPassword());
        replicationDataSource.setReplication("database");
        replicationDataSource.setPreferQueryMode(PreferQueryMode.SIMPLE);
        replicationDataSource.setAssumeMinServerVersion("14");

        final var router = new NotificationRouter(replicationDataSource);
        router.start();

        final var notification = Notification.newBuilder()
                .setTimestamp(Timestamps.now())
                .setGroup(Group.GROUP_PROJECT_CREATED)
                .setLevel(Level.LEVEL_INFORMATIONAL)
                .setScope(Scope.SCOPE_PORTFOLIO)
                .build();

        NotificationDispatcher.dispatch(qm, notification);

        qm.createProject("foo", "bar", "1.2.3", null, null, null, true, false);

        Thread.sleep(1000);

        router.close();
        router.start();

        await()
                .atMost(Duration.ofSeconds(15))
                .untilTrue(new AtomicBoolean(false));
    }

}