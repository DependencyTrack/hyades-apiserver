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
package org.dependencytrack.storage;

import org.dependencytrack.PersistenceCapableTest;
import org.jdbi.v3.core.statement.UnableToExecuteStatementException;
import org.junit.Test;
import org.postgresql.util.PSQLException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class DatabaseBomUploadStorageProviderTest extends PersistenceCapableTest {

    private final DatabaseBomUploadStorageProvider storageProvider = new DatabaseBomUploadStorageProvider();

    @Test
    public void testStoreBom() {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());

        final Optional<Integer> result = withJdbiHandle(handle -> handle
                .createQuery("SELECT 1 FROM \"BOM_UPLOAD\" WHERE \"TOKEN\" = :token")
                .bind("token", token)
                .mapTo(Integer.class)
                .findOne());
        assertThat(result).isPresent();
    }

    @Test
    public void testStoreBomDuplicate() {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());

        assertThatExceptionOfType(UnableToExecuteStatementException.class)
                .isThrownBy(() -> storageProvider.storeBom(token, "bar".getBytes()))
                .withRootCauseInstanceOf(PSQLException.class);
    }

    @Test
    public void testGetBom() {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());
        assertThat(storageProvider.getBomByToken(token)).asString().isEqualTo("foo");
    }

    @Test
    public void testDeleteBom() {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());
        assertThat(storageProvider.deleteBomByToken(token)).isTrue();

        final Optional<Integer> result = withJdbiHandle(handle -> handle
                .createQuery("SELECT 1 FROM \"BOM_UPLOAD\" WHERE \"TOKEN\" = :token")
                .bind("token", token)
                .mapTo(Integer.class)
                .findOne());
        assertThat(result).isNotPresent();
    }

    @Test
    public void testDeleteNonExistentBom() {
        assertThat(storageProvider.deleteBomByToken(UUID.randomUUID())).isFalse();
    }

}