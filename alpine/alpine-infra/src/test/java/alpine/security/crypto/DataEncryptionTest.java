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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class DataEncryptionTest {

    private DataEncryption dataEncryption;

    @BeforeEach
    void beforeEach() {
        // Use a hardcoded key for testing to avoid expensive generation.
        final SecretKey secretKey = new SecretKeySpec(
                Base64.getDecoder().decode("ACIUJnGyVVvaEIwcW58aTcqholameAxDkYOps+M6tcY="), 0, 32, "AES");

        final var keyManagerMock = mock(KeyManager.class);
        doReturn(secretKey).when(keyManagerMock).getSecretKey();

        dataEncryption = new DataEncryption(keyManagerMock);
    }

    @Test
    void encryptAndDecryptAsBytes1Test() throws Exception {
        byte[] bytes = dataEncryption.encryptAsBytes("This is encrypted text");
        Assertions.assertTrue(bytes.length > 0);
        Assertions.assertEquals("This is encrypted text", new String(dataEncryption.decryptAsBytes(bytes)));
    }

    @Test
    void encryptAndDecryptAsBytes2Test() throws Exception {
        byte[] bytes = dataEncryption.encryptAsBytes("This is encrypted text");
        Assertions.assertTrue(bytes.length > 0);
        Assertions.assertEquals("This is encrypted text", new String(dataEncryption.decryptAsBytes(bytes)));
    }

    @Test
    void encryptAndDecryptAsString1Test() throws Exception {
        String enc = dataEncryption.encryptAsString("This is encrypted text");
        Assertions.assertTrue(enc.length() > 0);
        Assertions.assertEquals("This is encrypted text", dataEncryption.decryptAsString(enc));
    }

    @Test
    void encryptAndDecryptAsString2Test() throws Exception {
        String enc = dataEncryption.encryptAsString("This is encrypted text");
        Assertions.assertTrue(enc.length() > 0);
        Assertions.assertEquals("This is encrypted text", dataEncryption.decryptAsString(enc));
    }
}
