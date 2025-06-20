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
package org.dependencytrack.auth;

import org.junit.Assert;
import org.junit.Test;

public class PermissionsTest {

    @Test
    public void testPermissionEnums() {
        Assert.assertEquals("ACCESS_MANAGEMENT", Permissions.ACCESS_MANAGEMENT.name());
        Assert.assertEquals("BADGES_READ", Permissions.BADGES_READ.name());
        Assert.assertEquals("BOM_READ", Permissions.BOM_READ.name());
        Assert.assertEquals("BOM_CREATE", Permissions.BOM_CREATE.name());
        Assert.assertEquals("FINDING_READ", Permissions.FINDING_READ.name());
        Assert.assertEquals("FINDING_UPDATE", Permissions.FINDING_UPDATE.name());
        Assert.assertEquals("FINDING_CREATE", Permissions.FINDING_CREATE.name());
        Assert.assertEquals("NOTIFICATION_RULE", Permissions.NOTIFICATION_RULE.name());
        Assert.assertEquals("POLICY", Permissions.POLICY.name());
        Assert.assertEquals("POLICY_VIOLATION_READ", Permissions.POLICY_VIOLATION_READ.name());
        Assert.assertEquals("POLICY_VIOLATION_UPDATE", Permissions.POLICY_VIOLATION_UPDATE.name());
        Assert.assertEquals("PORTFOLIO", Permissions.PORTFOLIO.name());
        Assert.assertEquals("PROJECT_READ", Permissions.PROJECT_READ.name());
        Assert.assertEquals("PROJECT_UPDATE", Permissions.PROJECT_UPDATE.name());
        Assert.assertEquals("PROJECT_DELETE", Permissions.PROJECT_DELETE.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION", Permissions.SYSTEM_CONFIGURATION.name());
        Assert.assertEquals("TAG", Permissions.TAG.name());
        Assert.assertEquals("VULNERABILITY", Permissions.VULNERABILITY.name());
    }

    @Test
    public void testPermissionConstants() {
        Assert.assertEquals("ACCESS_MANAGEMENT", Permissions.Constants.ACCESS_MANAGEMENT);
        Assert.assertEquals("BADGES_READ", Permissions.Constants.BADGES_READ);
        Assert.assertEquals("BOM_READ", Permissions.Constants.BOM_READ);
        Assert.assertEquals("BOM_CREATE", Permissions.Constants.BOM_CREATE);
        Assert.assertEquals("FINDING_READ", Permissions.Constants.FINDING_READ);
        Assert.assertEquals("FINDING_UPDATE", Permissions.Constants.FINDING_UPDATE);
        Assert.assertEquals("FINDING_CREATE", Permissions.Constants.FINDING_CREATE);
        Assert.assertEquals("NOTIFICATION_RULE", Permissions.Constants.NOTIFICATION_RULE);
        Assert.assertEquals("POLICY", Permissions.Constants.POLICY);
        Assert.assertEquals("POLICY_VIOLATION_READ", Permissions.Constants.POLICY_VIOLATION_READ);
        Assert.assertEquals("POLICY_VIOLATION_UPDATE", Permissions.Constants.POLICY_VIOLATION_UPDATE);
        Assert.assertEquals("PORTFOLIO", Permissions.Constants.PORTFOLIO);
        Assert.assertEquals("PROJECT_READ", Permissions.Constants.PROJECT_READ);
        Assert.assertEquals("PROJECT_UPDATE", Permissions.Constants.PROJECT_UPDATE);
        Assert.assertEquals("PROJECT_DELETE", Permissions.Constants.PROJECT_DELETE);
        Assert.assertEquals("SYSTEM_CONFIGURATION", Permissions.Constants.SYSTEM_CONFIGURATION);
        Assert.assertEquals("TAG", Permissions.Constants.TAG);
        Assert.assertEquals("VULNERABILITY", Permissions.Constants.VULNERABILITY);
    }
}
