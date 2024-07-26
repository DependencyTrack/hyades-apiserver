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

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.plugin.PluginManagerTestUtil.createConfigRegistry;

public class LocalBomUploadStorageTest {

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private Path tempDirPath;

    @Before
    public void before() throws Exception {
        tempDirPath = Files.createTempDirectory(null);
        tempDirPath.toFile().deleteOnExit();
    }

    @Test
    public void testFactoryName() {
        try (final var factory = new LocalBomUploadStorageFactory()) {
            assertThat(factory.extensionName()).isEqualTo("local");
        }
    }

    @Test
    public void testFactoryPriority() {
        try (final var factory = new LocalBomUploadStorageFactory()) {
            assertThat(factory.priority()).isEqualTo(110);
        }
    }

    @Test
    public void testStoreAndGetAndDeleteBom() throws Exception {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_LOCAL_DIRECTORY", tempDirPath.toString());

        try (final var factory = new LocalBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, LocalBomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            final var token = UUID.randomUUID();
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "foo".getBytes()));
            assertThat(storage.getBomByToken(token)).asString().isEqualTo("foo");
            assertThat(storage.deleteBomByToken(token)).isTrue();
            assertThat(storage.getBomByToken(token)).isNull();
        }
    }

    @Test
    public void testStoreAndGetAndDeleteBomWithDefaultDirectory() throws Exception {
        try (final var factory = new LocalBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, LocalBomUploadStorage.EXTENSION_NAME));
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
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_LOCAL_DIRECTORY", tempDirPath.toString());

        try (final var factory = new LocalBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, LocalBomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            final var token = UUID.randomUUID();
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "foo".getBytes()));
            assertThatNoException().isThrownBy(() -> storage.storeBom(token, "bar".getBytes()));
            assertThat(storage.getBomByToken(token)).asString().isEqualTo("bar");
        }
    }

    @Test
    public void testDeleteNonExistentBom() throws Exception {
        environmentVariables.set("BOM_UPLOAD_STORAGE_EXTENSION_LOCAL_DIRECTORY", tempDirPath.toString());

        try (final var factory = new LocalBomUploadStorageFactory()) {
            factory.init(createConfigRegistry(BomUploadStorageExtensionPointMetadata.EXTENSION_POINT_NAME, LocalBomUploadStorage.EXTENSION_NAME));
            final BomUploadStorage storage = factory.create();

            assertThat(storage.deleteBomByToken(UUID.randomUUID())).isFalse();
        }
    }

}