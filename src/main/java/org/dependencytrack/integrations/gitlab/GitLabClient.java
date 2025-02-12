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
package org.dependencytrack.integrations.gitlab;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.dependencytrack.auth.Permissions;
import org.json.JSONArray;

import alpine.common.logging.Logger;

public class GitLabClient {

    private static final Logger LOGGER = Logger.getLogger(GitLabClient.class);
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private final GitLabSyncer syncer;
    private final URL baseURL;

    public GitLabClient(final GitLabSyncer syncer, final URL baseURL) {
        this.syncer = syncer;
        this.baseURL = baseURL;
    }

    // JSONArray to ArrayList simple converter
    public ArrayList<String> jsonToList(final JSONArray jsonArray) {
        ArrayList<String> list = new ArrayList<>();

        for (Object o : jsonArray != null ? jsonArray : Collections.emptyList())
            list.add(o.toString());

        return list;
    }
    public Map<String, List<Permissions>> mapPermissionsToRoles() {
    Map<String, List<Permissions>> permissionMap = new HashMap<>();

    // Guest role
    List<Permissions> guestPermissions = Arrays.asList(
            Permissions.VIEW_PORTFOLIO,
            Permissions.VIEW_VULNERABILITY,
            Permissions.VIEW_BADGES
    );
    permissionMap.put("Guest", guestPermissions);

    // Reporter role
    List<Permissions> reporterPermissions = Arrays.asList(
            Permissions.VIEW_PORTFOLIO,
            Permissions.VIEW_VULNERABILITY,
            Permissions.VIEW_POLICY_VIOLATION,
            Permissions.VIEW_BADGES
    );
    permissionMap.put("Reporter", reporterPermissions);

    // Developer role
    List<Permissions> developerPermissions = Arrays.asList(
            Permissions.BOM_UPLOAD,
            Permissions.VIEW_PORTFOLIO,
            Permissions.PORTFOLIO_MANAGEMENT_READ,
            Permissions.VIEW_VULNERABILITY,
            Permissions.VULNERABILITY_ANALYSIS_READ,
            Permissions.PROJECT_CREATION_UPLOAD
    );
    permissionMap.put("Developer", developerPermissions);

    // Maintainer role
    List<Permissions> maintainerPermissions = Arrays.asList(
            Permissions.BOM_UPLOAD,
            Permissions.PORTFOLIO_MANAGEMENT,
            Permissions.PORTFOLIO_MANAGEMENT_CREATE,
            Permissions.PORTFOLIO_MANAGEMENT_READ,
            Permissions.PORTFOLIO_MANAGEMENT_UPDATE,
            Permissions.PORTFOLIO_MANAGEMENT_DELETE,
            Permissions.VULNERABILITY_ANALYSIS,
            Permissions.VULNERABILITY_ANALYSIS_CREATE,
            Permissions.VULNERABILITY_ANALYSIS_READ,
            Permissions.VULNERABILITY_ANALYSIS_UPDATE,
            Permissions.POLICY_MANAGEMENT,
            Permissions.POLICY_MANAGEMENT_CREATE,
            Permissions.POLICY_MANAGEMENT_READ,
            Permissions.POLICY_MANAGEMENT_UPDATE,
            Permissions.POLICY_MANAGEMENT_DELETE
    );
    permissionMap.put("Maintainer", maintainerPermissions);

    // Owner role
    List<Permissions> ownerPermissions = Arrays.asList(
            Permissions.ACCESS_MANAGEMENT,
            Permissions.ACCESS_MANAGEMENT_CREATE,
            Permissions.ACCESS_MANAGEMENT_READ,
            Permissions.ACCESS_MANAGEMENT_UPDATE,
            Permissions.ACCESS_MANAGEMENT_DELETE,
            Permissions.SYSTEM_CONFIGURATION,
            Permissions.SYSTEM_CONFIGURATION_CREATE,
            Permissions.SYSTEM_CONFIGURATION_READ,
            Permissions.SYSTEM_CONFIGURATION_UPDATE,
            Permissions.SYSTEM_CONFIGURATION_DELETE,
            Permissions.TAG_MANAGEMENT,
            Permissions.TAG_MANAGEMENT_DELETE
    );
    permissionMap.put("Owner", ownerPermissions);

    return permissionMap;
  }
}