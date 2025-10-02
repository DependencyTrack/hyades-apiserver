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

import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.ACCESS_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.BOM_UPLOAD;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.POLICY_VIOLATION_ANALYSIS;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.PROJECT_CREATION_UPLOAD;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_READ;
import static org.dependencytrack.auth.Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.TAG_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.TAG_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_BADGES;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_POLICY_VIOLATION;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_PORTFOLIO;
import static org.dependencytrack.auth.Permissions.Constants.VIEW_VULNERABILITY;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS_READ;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_CREATE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_DELETE;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_READ;
import static org.dependencytrack.auth.Permissions.Constants.VULNERABILITY_MANAGEMENT_UPDATE;

public class PermissionsTest {

    @Test
    public void testPermissionEnums() {
        Assert.assertEquals(38, Permissions.values().length);
        Assert.assertEquals("BOM_UPLOAD", Permissions.BOM_UPLOAD.name());
        Assert.assertEquals("VIEW_PORTFOLIO", Permissions.VIEW_PORTFOLIO.name());
        Assert.assertEquals("PORTFOLIO_ACCESS_CONTROL_BYPASS", Permissions.PORTFOLIO_ACCESS_CONTROL_BYPASS.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", Permissions.PORTFOLIO_MANAGEMENT.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_CREATE", Permissions.PORTFOLIO_MANAGEMENT_CREATE.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_READ", Permissions.PORTFOLIO_MANAGEMENT_READ.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_UPDATE", Permissions.PORTFOLIO_MANAGEMENT_UPDATE.name());
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_DELETE", Permissions.PORTFOLIO_MANAGEMENT_DELETE.name());
        Assert.assertEquals("VIEW_VULNERABILITY", Permissions.VIEW_VULNERABILITY.name());
        Assert.assertEquals("VULNERABILITY_ANALYSIS", Permissions.VULNERABILITY_ANALYSIS.name());
        Assert.assertEquals("VULNERABILITY_ANALYSIS_CREATE", Permissions.VULNERABILITY_ANALYSIS_CREATE.name());
        Assert.assertEquals("VULNERABILITY_ANALYSIS_READ", Permissions.VULNERABILITY_ANALYSIS_READ.name());
        Assert.assertEquals("VULNERABILITY_ANALYSIS_UPDATE", Permissions.VULNERABILITY_ANALYSIS_UPDATE.name());
        Assert.assertEquals("VIEW_POLICY_VIOLATION", Permissions.VIEW_POLICY_VIOLATION.name());
        Assert.assertEquals("VULNERABILITY_MANAGEMENT", Permissions.VULNERABILITY_MANAGEMENT.name());
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_CREATE", Permissions.VULNERABILITY_MANAGEMENT_CREATE.name());
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_READ", Permissions.VULNERABILITY_MANAGEMENT_READ.name());
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_UPDATE", Permissions.VULNERABILITY_MANAGEMENT_UPDATE.name());
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_DELETE", Permissions.VULNERABILITY_MANAGEMENT_DELETE.name());
        Assert.assertEquals("POLICY_VIOLATION_ANALYSIS", Permissions.POLICY_VIOLATION_ANALYSIS.name());
        Assert.assertEquals("ACCESS_MANAGEMENT", Permissions.ACCESS_MANAGEMENT.name());
        Assert.assertEquals("ACCESS_MANAGEMENT_CREATE", Permissions.ACCESS_MANAGEMENT_CREATE.name());
        Assert.assertEquals("ACCESS_MANAGEMENT_READ", Permissions.ACCESS_MANAGEMENT_READ.name());
        Assert.assertEquals("ACCESS_MANAGEMENT_UPDATE", Permissions.ACCESS_MANAGEMENT_UPDATE.name());
        Assert.assertEquals("ACCESS_MANAGEMENT_DELETE", Permissions.ACCESS_MANAGEMENT_DELETE.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION", Permissions.SYSTEM_CONFIGURATION.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION_CREATE", Permissions.SYSTEM_CONFIGURATION_CREATE.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION_READ", Permissions.SYSTEM_CONFIGURATION_READ.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION_UPDATE", Permissions.SYSTEM_CONFIGURATION_UPDATE.name());
        Assert.assertEquals("SYSTEM_CONFIGURATION_DELETE", Permissions.SYSTEM_CONFIGURATION_DELETE.name());
        Assert.assertEquals("PROJECT_CREATION_UPLOAD", Permissions.PROJECT_CREATION_UPLOAD.name());
        Assert.assertEquals("POLICY_MANAGEMENT", Permissions.POLICY_MANAGEMENT.name());
        Assert.assertEquals("POLICY_MANAGEMENT_CREATE", Permissions.POLICY_MANAGEMENT_CREATE.name());
        Assert.assertEquals("POLICY_MANAGEMENT_READ", Permissions.POLICY_MANAGEMENT_READ.name());
        Assert.assertEquals("POLICY_MANAGEMENT_UPDATE", Permissions.POLICY_MANAGEMENT_UPDATE.name());
        Assert.assertEquals("POLICY_MANAGEMENT_DELETE", Permissions.POLICY_MANAGEMENT_DELETE.name());
        Assert.assertEquals("TAG_MANAGEMENT", Permissions.TAG_MANAGEMENT.name());
        Assert.assertEquals("TAG_MANAGEMENT_DELETE", Permissions.TAG_MANAGEMENT_DELETE.name());
        Assert.assertEquals("VIEW_BADGES", Permissions.VIEW_BADGES.name());
    }

    @Test
    public void testPermissionConstants() {
        Assert.assertEquals("BOM_UPLOAD", BOM_UPLOAD);
        Assert.assertEquals("VIEW_PORTFOLIO", VIEW_PORTFOLIO);
        Assert.assertEquals("PORTFOLIO_ACCESS_CONTROL_BYPASS", PORTFOLIO_ACCESS_CONTROL_BYPASS);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT", PORTFOLIO_MANAGEMENT);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_CREATE", PORTFOLIO_MANAGEMENT_CREATE);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_READ", PORTFOLIO_MANAGEMENT_READ);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_UPDATE", PORTFOLIO_MANAGEMENT_UPDATE);
        Assert.assertEquals("PORTFOLIO_MANAGEMENT_DELETE", PORTFOLIO_MANAGEMENT_DELETE);
        Assert.assertEquals("VIEW_VULNERABILITY", VIEW_VULNERABILITY);
        Assert.assertEquals("VULNERABILITY_ANALYSIS", VULNERABILITY_ANALYSIS);
        Assert.assertEquals("VULNERABILITY_ANALYSIS_CREATE", VULNERABILITY_ANALYSIS_CREATE);
        Assert.assertEquals("VULNERABILITY_ANALYSIS_READ", VULNERABILITY_ANALYSIS_READ);
        Assert.assertEquals("VULNERABILITY_ANALYSIS_UPDATE", VULNERABILITY_ANALYSIS_UPDATE);
        Assert.assertEquals("VIEW_POLICY_VIOLATION", VIEW_POLICY_VIOLATION);
        Assert.assertEquals("VULNERABILITY_MANAGEMENT", VULNERABILITY_MANAGEMENT);
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_CREATE", VULNERABILITY_MANAGEMENT_CREATE);
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_READ", VULNERABILITY_MANAGEMENT_READ);
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_UPDATE", VULNERABILITY_MANAGEMENT_UPDATE);
        Assert.assertEquals("VULNERABILITY_MANAGEMENT_DELETE", VULNERABILITY_MANAGEMENT_DELETE);
        Assert.assertEquals("POLICY_VIOLATION_ANALYSIS", POLICY_VIOLATION_ANALYSIS);
        Assert.assertEquals("ACCESS_MANAGEMENT", ACCESS_MANAGEMENT);
        Assert.assertEquals("ACCESS_MANAGEMENT_CREATE", ACCESS_MANAGEMENT_CREATE);
        Assert.assertEquals("ACCESS_MANAGEMENT_READ", ACCESS_MANAGEMENT_READ);
        Assert.assertEquals("ACCESS_MANAGEMENT_UPDATE", ACCESS_MANAGEMENT_UPDATE);
        Assert.assertEquals("ACCESS_MANAGEMENT_DELETE", ACCESS_MANAGEMENT_DELETE);
        Assert.assertEquals("SYSTEM_CONFIGURATION", SYSTEM_CONFIGURATION);
        Assert.assertEquals("SYSTEM_CONFIGURATION_CREATE", SYSTEM_CONFIGURATION_CREATE);
        Assert.assertEquals("SYSTEM_CONFIGURATION_READ", SYSTEM_CONFIGURATION_READ);
        Assert.assertEquals("SYSTEM_CONFIGURATION_UPDATE", SYSTEM_CONFIGURATION_UPDATE);
        Assert.assertEquals("SYSTEM_CONFIGURATION_DELETE", SYSTEM_CONFIGURATION_DELETE);
        Assert.assertEquals("PROJECT_CREATION_UPLOAD", PROJECT_CREATION_UPLOAD);
        Assert.assertEquals("POLICY_MANAGEMENT", POLICY_MANAGEMENT);
        Assert.assertEquals("POLICY_MANAGEMENT_CREATE", POLICY_MANAGEMENT_CREATE);
        Assert.assertEquals("POLICY_MANAGEMENT_READ", POLICY_MANAGEMENT_READ);
        Assert.assertEquals("POLICY_MANAGEMENT_UPDATE", POLICY_MANAGEMENT_UPDATE);
        Assert.assertEquals("POLICY_MANAGEMENT_DELETE", POLICY_MANAGEMENT_DELETE);
        Assert.assertEquals("TAG_MANAGEMENT", TAG_MANAGEMENT);
        Assert.assertEquals("TAG_MANAGEMENT_DELETE", TAG_MANAGEMENT_DELETE);
        Assert.assertEquals("VIEW_BADGES", VIEW_BADGES);
    }
}
