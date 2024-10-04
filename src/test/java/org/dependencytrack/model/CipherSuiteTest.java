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
package org.dependencytrack.model;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;


public class CipherSuiteTest {

    @Test
    public void testCipherSuite() {
        CipherSuite cs = new CipherSuite();
        String name = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        List<String> algorithms = List.of(
            "crypto/algorithm/ecdh-curve25519@1.3.132.1.12",
            "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1",
            "crypto/algorithm/aes-256-gcm@2.16.840.1.101.3.4.1.46",
            "crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.9"
        );
        List<String> identifiers = List.of("a", "b", "c", "d");
        String location = "httpclient/src/main/java/org/apache/http/impl/auth/NTLMEngineImpl.java";
        String addittionalContext = "javax.crypto.spec.SecretKeySpec#<init>([BLjava/lang/String;)V";
        String bomRef = "471d7b60-0e38-4373-9e66-799d9fbea5de";
        cs.setAlgorithms(algorithms);
        cs.setName(name);
        cs.setIdentifiers(identifiers);

        Assert.assertEquals(algorithms, cs.getAlgorithms());
        Assert.assertEquals(name, cs.getName());
        Assert.assertEquals(identifiers, cs.getIdentifiers());
    }
}
