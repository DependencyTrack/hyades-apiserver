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

import alpine.model.AccessLevel;
import alpine.model.AccessResource;

/**
 * Defines permissions specific to Dependency-Track.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public enum Permissions {
    // @formatter:off
    ACCESS_MANAGEMENT(AccessResource.ACCESS_MANAGEMENT, AccessLevel.SYSTEM, "Allows the management of users, teams, and API keys"),
    BADGES_READ(AccessResource.BADGES, AccessLevel.READ, "Provides the ability to view badges"),
    BOM_READ(AccessResource.BOM, AccessLevel.READ, "Allows the ability to view CycloneDX Software Bill of Materials (SBOM)"),
    BOM_CREATE(AccessResource.BOM, AccessLevel.CREATE, "Allows the ability to upload CycloneDX Software Bill of Materials (SBOM)"),
    FINDING_READ(AccessResource.FINDING, AccessLevel.READ, "Provides the ability read the VEX document for a project"),
    FINDING_UPDATE(AccessResource.FINDING, AccessLevel.UPDATE, "Provides the ability to make analysis decisions on vulnerabilities and upload supported VEX documents for a project"),
    FINDING_CREATE(AccessResource.FINDING, AccessLevel.CREATE, "Provides the ability to upload supported VEX documents to a project"),
    NOTIFICATION_RULE(AccessResource.NOTIFICATION_RULE, AccessLevel.SYSTEM, "Allows configuration of notifications and email settings"),
    POLICY(AccessResource.POLICY, AccessLevel.SYSTEM, "Allows the creation, modification, and deletion of policy"),
    POLICY_VIOLATION_READ(AccessResource.POLICY_VIOLATION, AccessLevel.READ, "Provides the ability to view policy violations"),
    POLICY_VIOLATION_UPDATE(AccessResource.POLICY_VIOLATION, AccessLevel.UPDATE, "Provides the ability to make analysis decisions on policy violations"),
    POLICY_VIOLATION_CREATE(AccessResource.POLICY_VIOLATION, AccessLevel.CREATE, null),
    PORTFOLIO(AccessResource.PORTFOLIO, AccessLevel.SYSTEM, "Allows the creation, modification, and deletion of data in the portfolio"),
    PROJECT_READ(AccessResource.PROJECT, AccessLevel.READ, null),
    PROJECT_UPDATE(AccessResource.PROJECT, AccessLevel.UPDATE, null),
    PROJECT_DELETE(AccessResource.PROJECT, AccessLevel.DELETE, null),
    SYSTEM_CONFIGURATION(AccessResource.SYSTEM_CONFIGURATION, AccessLevel.SYSTEM, "Allows all access to configuration of the system including notifications, repositories, and email settings"),
    TAG(AccessResource.TAG, AccessLevel.SYSTEM, "Allows the management of global tag definitions"),
    VULNERABILITY(AccessResource.VULNERABILITY, AccessLevel.SYSTEM, "Allows the management of custom vulnerabilities");
    // @formatter:on

    private final AccessResource resource;
    private final AccessLevel accessLevel;
    private final String description;

    Permissions(final AccessResource resource, final AccessLevel accessLevel, final String description) {
        this.resource = resource;
        this.accessLevel = accessLevel;
        this.description = description;
    }

    public AccessResource getResource() {
        return resource;
    }

    public AccessLevel getAccessLevel() {
        return accessLevel;
    }

    public String getDescription() {
        return description;
    }

    public static class Constants {
        public static final String BADGES_READ = "BADGES_READ";
        public static final String BOM_READ = "BOM_READ";
        public static final String BOM_CREATE = "BOM_CREATE";
        public static final String FINDING_READ = "FINDING_READ";
        public static final String FINDING_UPDATE = "FINDING_UPDATE";
        public static final String FINDING_CREATE = "FINDING_CREATE";
        public static final String NOTIFICATION_RULE = "NOTIFICATION_RULE";
        public static final String POLICY = "POLICY";
        public static final String POLICY_VIOLATION_READ = "POLICY_VIOLATION_READ";
        public static final String POLICY_VIOLATION_UPDATE = "POLICY_VIOLATION_UPDATE";
        public static final String POLICY_VIOLATION_CREATE = "POLICY_VIOLATION_CREATE";
        public static final String PORTFOLIO = "PORTFOLIO";
        public static final String PROJECT_READ = "PROJECT_READ";
        public static final String PROJECT_UPDATE = "PROJECT_UPDATE";
        public static final String PROJECT_DELETE = "PROJECT_DELETE";
        public static final String TAG = "TAG";
        public static final String VULNERABILITY = "VULNERABILITY";
    }

}
