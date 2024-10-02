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

import org.junit.Assert;
import org.junit.Test;


public class OccurrenceTest {

    @Test
    public void testOccurrence() {
        Occurrence o = new Occurrence();

        String location = "httpclient/src/main/java/org/apache/http/impl/auth/NTLMEngineImpl.java";
        String addittionalContext = "javax.crypto.spec.SecretKeySpec#<init>([BLjava/lang/String;)V";
        String bomRef = "471d7b60-0e38-4373-9e66-799d9fbea5de";
        o.setLine(585);
        o.setOffset(42);
        o.setLocation(location);
        o.setAdditionalContext(addittionalContext);
        o.setSymbol(0);
        o.setBomRef(bomRef);

        Assert.assertEquals((Integer)585, o.getLine());
        Assert.assertEquals((Integer)42, o.getOffset());
        Assert.assertEquals(location, o.getLocation());
        Assert.assertEquals(addittionalContext, o.getAdditionalContext());
        Assert.assertEquals(bomRef, o.getBomRef());
    }
}
