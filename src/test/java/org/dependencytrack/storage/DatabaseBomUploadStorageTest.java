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
import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.plugin.PluginManagerTestUtil.createConfigRegistry;

public class DatabaseBomUploadStorageTest extends PersistenceCapableTest {

    @Test
    public void testFactoryName() {
        try (final var factory = new DatabaseBomUploadStorageFactory()) {
            assertThat(factory.extensionName()).isEqualTo("database");
        }
    }

    @Test
    public void testFactoryPriority() {
        try (final var factory = new DatabaseBomUploadStorageFactory()) {
            assertThat(factory.priority()).isEqualTo(100);
        }
    }

    @Test
    public void testStoreAndGetAndDeleteBom() throws Exception {
        try (final var factory = new DatabaseBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, DatabaseBomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            final var token = UUID.randomUUID();
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "foo".getBytes()));
            assertThat(storage.getBomByToken(token)).asString().isEqualTo("foo");
            assertThat(storage.deleteBomByToken(token)).isTrue();
            assertThat(storage.getBomByToken(token)).isNull();
        }
    }

    @Test
    public void testStoreBomDuplicate() throws Exception {
        try (final var factory = new DatabaseBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, DatabaseBomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            final var token = UUID.randomUUID();
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "foo".getBytes()));
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "bar".getBytes()));
            assertThat(storage.getBomByToken(token)).asString().isEqualTo("bar");
        }
    }

    @Test
    public void testDeleteNonExistentBom() throws Exception {
        try (final var factory = new DatabaseBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, S3BomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            assertThat(storage.deleteBomByToken(UUID.randomUUID())).isFalse();
        }
    }

}