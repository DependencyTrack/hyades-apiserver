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

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.dependencytrack.auth.Permissions;

/**
 * Definitions of access levels/roles as defined by GitLab.
 */
public enum GitLabRole {

    GUEST(10, "GitLab Project Guest", Set.of( // Applies to private and internal projects only
            Permissions.Constants.VIEW_PORTFOLIO,
            Permissions.Constants.VIEW_VULNERABILITY,
            Permissions.Constants.VIEW_BADGES)),
    PLANNER(15, "GitLab Project Planner", Set.of(
            Permissions.Constants.VIEW_POLICY_VIOLATION)),
    REPORTER(20, "GitLab Project Reporter", Set.of(
            Permissions.Constants.VIEW_POLICY_VIOLATION)),
    DEVELOPER(30, "GitLab Project Developer", Set.of(
            Permissions.Constants.BOM_UPLOAD,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_READ,
            Permissions.Constants.VULNERABILITY_ANALYSIS_READ,
            Permissions.Constants.PROJECT_CREATION_UPLOAD)),
    MAINTAINER(40, "GitLab Project Maintainer", Set.of(
            Permissions.Constants.PORTFOLIO_MANAGEMENT,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE,
            Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE,
            Permissions.Constants.VULNERABILITY_ANALYSIS,
            Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE,
            Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE,
            Permissions.Constants.POLICY_MANAGEMENT,
            Permissions.Constants.POLICY_MANAGEMENT_CREATE,
            Permissions.Constants.POLICY_MANAGEMENT_READ,
            Permissions.Constants.POLICY_MANAGEMENT_UPDATE,
            Permissions.Constants.POLICY_MANAGEMENT_DELETE)),
    OWNER(50, "GitLab Project Owner", Set.of(
            Permissions.Constants.ACCESS_MANAGEMENT,
            Permissions.Constants.ACCESS_MANAGEMENT_CREATE,
            Permissions.Constants.ACCESS_MANAGEMENT_READ,
            Permissions.Constants.ACCESS_MANAGEMENT_UPDATE,
            Permissions.Constants.ACCESS_MANAGEMENT_DELETE,
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE,
            Permissions.Constants.TAG_MANAGEMENT,
            Permissions.Constants.TAG_MANAGEMENT_DELETE));

    private final int accessLevel;
    private final String description;
    private final Set<String> permissions;

    GitLabRole(final int accessLevel, final String description, final Set<String> permissions) {
        this.accessLevel = accessLevel;
        this.description = description;
        this.permissions = permissions;
    }

    public int getAccessLevel() {
        return accessLevel;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Get a set of permissions consisting of this role's permissions
     * combined with permissions from the roles with lesser access levels.
     *
     * @return A sorted set of permissions for this role.
     */
public Set<String> getPermissions() {
    return Stream.of(GitLabRole.values())
            .filter(value -> value.getAccessLevel() <= this.accessLevel) // Include current and lower access levels
            .flatMap(value -> value.permissions.stream()) // Flatten permissions from all roles
            .collect(Collectors.toCollection(LinkedHashSet::new)); // Collect into a LinkedHashSet to maintain order
}
}
