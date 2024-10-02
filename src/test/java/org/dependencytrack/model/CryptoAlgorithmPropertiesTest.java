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

import org.cyclonedx.model.component.crypto.enums.CertificationLevel;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.ExecutionEnvironment;
import org.cyclonedx.model.component.crypto.enums.ImplementationPlatform;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.junit.Assert;
import org.junit.Test;


public class CryptoAlgorithmPropertiesTest {

    @Test
    public void testCryptoAlgorithmProperties() {
        CryptoAlgorithmProperties cap = new CryptoAlgorithmProperties();
        cap.setPrimitive(Primitive.AE);
        cap.setParameterSetIdentifier("128");
        cap.setExecutionEnvironment(ExecutionEnvironment.SOFTWARE_PLAIN_RAM);
        cap.setImplementationPlatform(ImplementationPlatform.X86_64);
        cap.setCertificationLevel(CertificationLevel.NONE);
        cap.setMode(Mode.CBC);
        cap.setPadding(Padding.RAW);
        List<CryptoFunction> cf = List.of(CryptoFunction.DECRYPT);
        cap.setCryptoFunctions(cf);
        cap.setClassicalSecurityLevel(0);
        cap.setNistQuantumSecurityLevel(0);

        Assert.assertEquals(Primitive.AE, cap.getPrimitive());
        Assert.assertEquals("128", cap.getParameterSetIdentifier());
        Assert.assertEquals(ExecutionEnvironment.SOFTWARE_PLAIN_RAM, cap.getExecutionEnvironment());
        Assert.assertEquals(ImplementationPlatform.X86_64, cap.getImplementationPlatform());
        Assert.assertEquals(CertificationLevel.NONE, cap.getCertificationLevel());
        Assert.assertEquals(Mode.CBC, cap.getMode());
        Assert.assertEquals(Padding.RAW, cap.getPadding());
        Assert.assertEquals(cf, cap.getCryptoFunctions());
        Assert.assertEquals((Integer)0, cap.getClassicalSecurityLevel());
        Assert.assertEquals((Integer)0, cap.getNistQuantumSecurityLevel());
    }
}
