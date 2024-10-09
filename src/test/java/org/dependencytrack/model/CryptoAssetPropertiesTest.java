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

import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.junit.Assert;
import org.junit.Test;


public class CryptoAssetPropertiesTest {

    @Test
    public void testAssetType() {
        CryptoAssetProperties cap = new CryptoAssetProperties();
        cap.setAssetType(AssetType.ALGORITHM);
        Assert.assertEquals(AssetType.ALGORITHM, cap.getAssetType());
    }

    @Test
    public void testAlgorithmProperties() {
        CryptoAssetProperties cap = new CryptoAssetProperties();
        CryptoAlgorithmProperties alg = new CryptoAlgorithmProperties();
        cap.setAssetType(AssetType.ALGORITHM);
        cap.setAlgorithmProperties(alg);
        Assert.assertEquals(AssetType.ALGORITHM, cap.getAssetType());
        Assert.assertEquals(alg, cap.getAlgorithmProperties());
    }

    @Test
    public void testCertificateProperties() {
        CryptoAssetProperties cap = new CryptoAssetProperties();
        CryptoCertificateProperties cert = new CryptoCertificateProperties();
        cap.setAssetType(AssetType.CERTIFICATE);
        cap.setCertificateProperties(cert);
        Assert.assertEquals(AssetType.CERTIFICATE, cap.getAssetType());
        Assert.assertEquals(cert, cap.getCertificateProperties());
    }

    @Test
    public void testRelatedMaterialProperties() {
        CryptoAssetProperties cap = new CryptoAssetProperties();
        CryptoRelatedMaterialProperties rel = new CryptoRelatedMaterialProperties();
        cap.setAssetType(AssetType.RELATED_CRYPTO_MATERIAL);
        cap.setRelatedMaterialProperties(rel);
        Assert.assertEquals(AssetType.RELATED_CRYPTO_MATERIAL, cap.getAssetType());
        Assert.assertEquals(rel, cap.getRelatedMaterialProperties());
    }

    @Test
    public void testProtocolProperties() {
        CryptoAssetProperties cap = new CryptoAssetProperties();
        CryptoProtocolProperties cpp = new CryptoProtocolProperties();
        cap.setAssetType(AssetType.PROTOCOL);
        cap.setProtocolProperties(cpp);
        Assert.assertEquals(AssetType.PROTOCOL, cap.getAssetType());
        Assert.assertEquals(cpp, cap.getProtocolProperties());
    }

    @Test
    public void testOid() {
        CryptoAssetProperties cap = new CryptoAssetProperties();
        String oid = "oid:2.16.840.1.101.3.4.1.6";
        cap.setOid(oid);
        Assert.assertEquals(oid, cap.getOid());
    }
}
