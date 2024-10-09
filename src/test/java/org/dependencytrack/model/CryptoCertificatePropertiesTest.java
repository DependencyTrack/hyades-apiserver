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

import org.dependencytrack.util.DateUtil;
import org.junit.Assert;
import org.junit.Test;


public class CryptoCertificatePropertiesTest {

    @Test
    public void testCryptoCertificateProperties() {
        CryptoCertificateProperties ccp = new CryptoCertificateProperties();
        String subject = "CN = www.google.com";
        String issuer = "C = US, O = Google Trust Services LLC, CN = GTS CA 1C3";
        String notValidBefore = "2016-11-21T08:00:00Z";
        String notValidAfter = "2017-11-22T07:59:59Z";
        String signatureAlgorithmRef =  "crypto/algorithm/sha-512-rsa@1.2.840.113549.1.1.13";
        String subjectPublicKeyRef = "crypto/key/rsa-2048@1.2.840.113549.1.1.1";
        String certificateFormat =  "X.509";
        String certificateExtension = "crt";
        ccp.setSubjectName(subject);
        ccp.setIssuerName(issuer);
        ccp.setNotValidBefore(notValidBefore);
        ccp.setNotValidAfter(notValidAfter);
        ccp.setSignatureAlgorithmRef(signatureAlgorithmRef);
        ccp.setSubjectPublicKeyRef(subjectPublicKeyRef);
        ccp.setCertificateExtension(certificateExtension);
        ccp.setCertificateFormat(certificateFormat);

        Assert.assertEquals(subject, ccp.getSubjectName());
        Assert.assertEquals(issuer, ccp.getIssuerName());
        Assert.assertEquals(DateUtil.fromISO8601(notValidBefore), ccp.getNotValidBefore());
        Assert.assertEquals(DateUtil.fromISO8601(notValidAfter), ccp.getNotValidAfter());
        Assert.assertEquals(signatureAlgorithmRef, ccp.getSignatureAlgorithmRef());
        Assert.assertEquals(subjectPublicKeyRef, ccp.getSubjectPublicKeyRef());
        Assert.assertEquals(certificateExtension, ccp.getCertificateExtension());
        Assert.assertEquals(certificateFormat, ccp.getCertificateFormat());
    }
}
