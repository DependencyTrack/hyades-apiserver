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
package org.dependencytrack.tasks;

import alpine.Config;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.HouseKeepingEvent;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.junit.Test;

import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class HouseKeepingTaskTest extends PersistenceCapableTest {

    @Test
    public void testBomUploadRetentionEnforcement() {
        useJdbiTransaction(handle -> {
            final PreparedBatch batch = handle.prepareBatch("""
                    INSERT INTO "BOM_UPLOAD" ("TOKEN", "UPLOADED_AT", "BOM")
                    VALUES (:token, NOW() - :uploadedDurationAgo, :bom)
                    """);

            for (int i = 1; i <= 10; i++) {
                final UUID token = UUID.randomUUID();
                final Duration uploadedDurationAgo = Duration.ofMinutes(i * 10);
                final byte[] bomBytes = "bom-%d".formatted(i).getBytes();

                batch.bind("token", token);
                batch.bind("uploadedDurationAgo", uploadedDurationAgo);
                batch.bind("bom", bomBytes);
                batch.add();
            }

            assertThat(Arrays.stream(batch.execute()).sum()).isEqualTo(10);
        });

        final var configMock = mock(Config.class);
        doReturn("PT1H").when(configMock).getProperty(eq(ConfigKey.BOM_UPLOAD_STORAGE_RETENTION_DURATION));

        final var task = new HouseKeepingTask(configMock);
        assertThatNoException().isThrownBy(() -> task.inform(new HouseKeepingEvent()));

        final int remainingBoms = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "BOM_UPLOAD"
                        """)
                .mapTo(Integer.class)
                .one());
        assertThat(remainingBoms).isEqualTo(5);
    }

}