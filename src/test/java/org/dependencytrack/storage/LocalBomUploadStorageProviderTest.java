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
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class LocalBomUploadStorageProviderTest {

    private Path tempDirPath;
    private LocalBomUploadStorageProvider storageProvider;

    @Before
    public void setUp() throws Exception {
        tempDirPath = Files.createTempDirectory(null);
        tempDirPath.toFile().deleteOnExit();

        storageProvider = new LocalBomUploadStorageProvider(tempDirPath);
    }

    @Test
    public void testStoreBom() throws Exception {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());
        assertThat(tempDirPath.resolve(token.toString())).exists();
    }

    @Test
    public void testGetBom() throws Exception {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());
        assertThat(storageProvider.getBomByToken(token)).asString().isEqualTo("foo");
    }

    @Test
    public void testDeleteBom() throws Exception {
        final var token = UUID.randomUUID();
        storageProvider.storeBom(token, "foo".getBytes());
        assertThat(storageProvider.deleteBomByToken(token)).isTrue();
        assertThat(tempDirPath.resolve(token.toString())).doesNotExist();
    }

    @Test
    public void testDeleteNonExistentBom() throws Exception {
        assertThat(storageProvider.deleteBomByToken(UUID.randomUUID())).isFalse();
    }

}