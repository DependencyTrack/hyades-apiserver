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

import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.junit.Assert;
import org.junit.Test;


public class CryptoProtocolPropertiesTest {

    @Test
    public void testCryptoProtocolProperties() {
        CryptoProtocolProperties cpp = new CryptoProtocolProperties();

        String version = "1.2";
        CipherSuite cs = new CipherSuite();
        cs.setName("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        cs.setAlgorithms(List.of("crypto/algorithm/sha-384@2.16.840.1.101.3.4.2.9"));
        cs.setIdentifiers(List.of("some id"));
        List<CipherSuite> ciphersuites = List.of(cs);
        Ikev2Type ikev2Type = new Ikev2Type();
        ikev2Type.setType("encr");
        ikev2Type.setRefs(null);
        List<Ikev2Type> ikev2Types = List.of(ikev2Type);
        List<String> cryptoRefs = List.of("crypto/algorithm/ecdh-curve25519@1.3.132.1.12");

        cpp.setType(ProtocolType.TLS);
        cpp.setVersion(version);
        cpp.setCipherSuites(ciphersuites);
        cpp.setIkev2Types(ikev2Types);
        cpp.setCryptoRefs(cryptoRefs);
        
        Assert.assertEquals(ProtocolType.TLS, cpp.getType());
        Assert.assertEquals(version, cpp.getVersion());
        Assert.assertEquals(ciphersuites, cpp.getCipherSuites());
        Assert.assertEquals(ikev2Types, cpp.getIkev2Types());
        Assert.assertEquals(cryptoRefs, cpp.getCryptoRefs());
    }
}
