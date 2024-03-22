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
package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class NewVulnerableDependencyTest {

    @Test
    public void testVo() {
        Component component = new Component();
        Set<Vulnerability> vulns = new HashSet<>();
        Vulnerability vuln = new Vulnerability();
        vulns.add(vuln);
        NewVulnerableDependency vo = new NewVulnerableDependency(component, vulns);
        Assert.assertEquals(component, vo.component());
        Assert.assertEquals(1, vo.vulnerabilities().size());
        Assert.assertEquals(vuln, vo.vulnerabilities().stream().findFirst().get());
    }
}
