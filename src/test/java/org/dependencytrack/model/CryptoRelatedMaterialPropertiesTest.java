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

import org.cyclonedx.model.component.crypto.enums.Mechanism;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.cyclonedx.model.component.crypto.enums.State;
import org.dependencytrack.util.DateUtil;
import org.junit.Assert;
import org.junit.Test;


public class CryptoRelatedMaterialPropertiesTest {

    @Test
    public void testCryptoRelatedMaterialProperties() {
        CryptoRelatedMaterialProperties rel = new CryptoRelatedMaterialProperties();
        String identifier = "2e9ef09e-dfac-4526-96b4-d02f31af1b22";
        String algorithmRef = "crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1";
        String creationDate = "2016-11-21T08:00:00Z";
        String activationDate = "2016-11-21T08:20:00Z";
        String updateDate = "2016-11-21T08:40:00Z";
        String expirationDate = "2016-11-21T09:00:00Z";
        String value = "some value";
        String format = "pem";
        String securedByAlgorithmRef = "crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13";
        rel.setType(RelatedCryptoMaterialType.DIGEST);
        rel.setIdentifier(identifier);
        rel.setState(State.ACTIVE);
        rel.setAlgorithmRef(algorithmRef);
        rel.setCreationDate(creationDate);
        rel.setActivationDate(activationDate);
        rel.setUpdateDate(updateDate);
        rel.setExpirationDate(expirationDate);
        rel.setValue(value);
        rel.setSize(2048);
        rel.setFormat(format);
        rel.setSecuredByAlgorithmRef(securedByAlgorithmRef);
        rel.setSecuredByMechanism(Mechanism.SOFTWARE);

        Assert.assertEquals(RelatedCryptoMaterialType.DIGEST, rel.getType());
        Assert.assertEquals(identifier, rel.getIdentifier());
        Assert.assertEquals(State.ACTIVE, rel.getState());
        Assert.assertEquals(algorithmRef, rel.getAlgorithmRef());
        Assert.assertEquals(DateUtil.fromISO8601(creationDate), rel.getCreationDate());
        Assert.assertEquals(DateUtil.fromISO8601(activationDate), rel.getActivationDate());
        Assert.assertEquals(DateUtil.fromISO8601(updateDate), rel.getUpdateDate());
        Assert.assertEquals(DateUtil.fromISO8601(expirationDate), rel.getExpirationDate());
        Assert.assertEquals(value, rel.getValue());
        Assert.assertEquals((Integer)2048, rel.getSize());
        Assert.assertEquals(format, rel.getFormat());
        Assert.assertEquals(securedByAlgorithmRef, rel.getSecuredByAlgorithmRef());
        Assert.assertEquals(Mechanism.SOFTWARE, rel.getSecuredByMechanism());
    }
}
