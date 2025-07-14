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
        Assert.assertEquals("BOM_CREATE", Permissions.BOM_CREATE.name());
        Assert.assertEquals("BOM_READ", Permissions.BOM_READ.name());
        Assert.assertEquals("FINDING_CREATE", Permissions.FINDING_CREATE.name());
        Assert.assertEquals("FINDING_READ", Permissions.FINDING_READ.name());
        Assert.assertEquals("FINDING_UPDATE", Permissions.FINDING_UPDATE.name());
        Assert.assertEquals("NOTIFICATION_RULE_MANAGEMENT", Permissions.NOTIFICATION_RULE_MANAGEMENT.name());
        Assert.assertEquals("POLICY_MANAGEMENT", Permissions.POLICY_MANAGEMENT.name());
        Assert.assertEquals("POLICY_VIOLATION_CREATE", Permissions.POLICY_VIOLATION_CREATE.name());
        Assert.assertEquals("POLICY_VIOLATION_READ", Permissions.POLICY_VIOLATION_READ.name());
        Assert.assertEquals("POLICY_VIOLATION_UPDATE", Permissions.POLICY_VIOLATION_UPDATE.name());
        Assert.assertEquals("PORTFOLIO_ACCESS_CONTROL_BYPASS", Permissions.PORTFOLIO_ACCESS_CONTROL_BYPASS.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", Permissions.PORTFOLIO_MANAGEMENT.name());
        Assert.assertEquals("PROJECT_DELETE", Permissions.PROJECT_DELETE.name());
        Assert.assertEquals("PROJECT_READ", Permissions.PROJECT_READ.name());
        Assert.assertEquals("PROJECT_UPDATE", Permissions.PROJECT_UPDATE.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION", Permissions.SYSTEM_CONFIGURATION.name());
        Assert.assertEquals("TAG_MANAGEMENT", Permissions.TAG_MANAGEMENT.name());
        Assert.assertEquals("VULNERABILITY_MANAGEMENT", Permissions.VULNERABILITY_MANAGEMENT.name());
    }

    @Test
    public void testPermissionConstants() {
        Assert.assertEquals("ACCESS_MANAGEMENT", Permissions.Constants.ACCESS_MANAGEMENT);
        Assert.assertEquals("BADGES_READ", Permissions.Constants.BADGES_READ);
        Assert.assertEquals("BOM_CREATE", Permissions.Constants.BOM_CREATE);
        Assert.assertEquals("BOM_READ", Permissions.Constants.BOM_READ);
        Assert.assertEquals("FINDING_CREATE", Permissions.Constants.FINDING_CREATE);
        Assert.assertEquals("FINDING_READ", Permissions.Constants.FINDING_READ);
        Assert.assertEquals("FINDING_UPDATE", Permissions.Constants.FINDING_UPDATE);
        Assert.assertEquals("NOTIFICATION_RULE_MANAGEMENT", Permissions.Constants.NOTIFICATION_RULE_MANAGEMENT);
        Assert.assertEquals("POLICY_MANAGEMENT", Permissions.Constants.POLICY_MANAGEMENT);
        Assert.assertEquals("POLICY_VIOLATION_CREATE", Permissions.Constants.POLICY_VIOLATION_CREATE);
        Assert.assertEquals("POLICY_VIOLATION_READ", Permissions.Constants.POLICY_VIOLATION_READ);
        Assert.assertEquals("POLICY_VIOLATION_UPDATE", Permissions.Constants.POLICY_VIOLATION_UPDATE);
        Assert.assertEquals("PORTFOLIO_ACCESS_CONTROL_BYPASS", Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", Permissions.Constants.PORTFOLIO_MANAGEMENT);
        Assert.assertEquals("PROJECT_DELETE", Permissions.Constants.PROJECT_DELETE);
        Assert.assertEquals("PROJECT_READ", Permissions.Constants.PROJECT_READ);
        Assert.assertEquals("PROJECT_UPDATE", Permissions.Constants.PROJECT_UPDATE);
        Assert.assertEquals("SYSTEM_CONFIGURATION", Permissions.Constants.SYSTEM_CONFIGURATION);
        Assert.assertEquals("TAG_MANAGEMENT", Permissions.Constants.TAG_MANAGEMENT);
        Assert.assertEquals("VULNERABILITY_MANAGEMENT", Permissions.Constants.VULNERABILITY_MANAGEMENT);
    }

}
