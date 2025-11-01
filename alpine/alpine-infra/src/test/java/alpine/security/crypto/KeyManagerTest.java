/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.security.crypto;

import alpine.Config;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import java.nio.file.Path;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class KeyManagerTest {

    @TempDir
    private Path tempDir;
    private KeyManager keyManager;

    @BeforeEach
    void beforeEach() {
        final var configMock = mock(Config.class);
        doReturn(tempDir.toFile()).when(configMock).getDataDirectorty();
        doReturn(null).when(configMock).getProperty(eq(Config.AlpineKey.SECRET_KEY_PATH));

        keyManager = new KeyManager(configMock);
    }

    @Test
    void secretKeyTest() throws Exception {
        SecretKey secretKey = keyManager.generateSecretKey();
        Assertions.assertEquals("AES", secretKey.getAlgorithm());
        Assertions.assertEquals("RAW", secretKey.getFormat());
        keyManager.save(secretKey);
        Assertions.assertTrue(keyManager.secretKeyExists());
        Assertions.assertEquals(secretKey, keyManager.getSecretKey());
    }

    @Test
    void saveAndLoadSecretKeyInLegacyFormatTest() throws Exception {
        final SecretKey secretKey = keyManager.generateSecretKey();
        keyManager.save(secretKey);
        final SecretKey loadedKey = keyManager.loadSecretKey();
        Assertions.assertArrayEquals(secretKey.getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void saveAndLoadSecretKeyInEncodedFormatTest() throws Exception {
        final SecretKey secretKey = keyManager.generateSecretKey();
        keyManager.saveEncoded(secretKey);
        final SecretKey loadedKey = keyManager.loadEncodedSecretKey();
        Assertions.assertArrayEquals(secretKey.getEncoded(), loadedKey.getEncoded());
    }

    @Test
    void secretKeyHasOldFormatTest() throws Exception {
        final SecretKey secretKey = keyManager.generateSecretKey();
        keyManager.save(secretKey);
        Assertions.assertTrue(keyManager.secretKeyHasOldFormat());
        keyManager.saveEncoded(secretKey);
        Assertions.assertFalse(keyManager.secretKeyHasOldFormat());
    }

}
