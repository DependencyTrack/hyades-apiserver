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

/**
 * Defines permissions specific to Dependency-Track.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public enum Permissions {

    // @formatter:off
    ACCESS_MANAGEMENT("Allows the management of users, teams, and API keys", Scope.SYSTEM),
    BADGES_READ("Provides the ability to view badges", Scope.PROJECT),
    BOM_CREATE("Allows the ability to upload CycloneDX Software Bill of Materials (SBOM)", Scope.PROJECT),
    BOM_READ("Allows the ability to view CycloneDX Software Bill of Materials (SBOM)", Scope.PROJECT),
    FINDING_CREATE("Provides the ability to upload supported VEX documents to a project", Scope.PROJECT),
    FINDING_READ("Provides the ability read the VEX document for a project", Scope.PROJECT),
    FINDING_UPDATE("Provides the ability to make analysis decisions on vulnerabilities and upload supported VEX documents for a project", Scope.PROJECT),
    NOTIFICATION_RULE("Allows configuration of notifications and email settings", Scope.SYSTEM),
    POLICY_VIOLATION_CREATE("Provides the ability to create policy violations", Scope.PROJECT),
    POLICY_VIOLATION_READ("Provides the ability to view policy violations", Scope.PROJECT),
    POLICY_VIOLATION_UPDATE("Provides the ability to make analysis decisions on policy violations", Scope.PROJECT),
    POLICY("Allows the creation, modification, and deletion of policy", Scope.SYSTEM),
    PORTFOLIO_ACCESS_CONTROL_BYPASS("Provides the ability to bypass portfolio access control, granting access to all projects", Scope.SYSTEM),
    PORTFOLIO("Allows the creation, modification, and deletion of data in the portfolio", Scope.SYSTEM),
    PROJECT_DELETE("Provides the ability to delete resources within a project", Scope.PROJECT),
    PROJECT_READ("Provides the ability to read resources within a project", Scope.PROJECT),
    PROJECT_UPDATE("Provides the ability to update resources within a project", Scope.PROJECT),
    SYSTEM_CONFIGURATION("Allows all access to configuration of the system including notifications, repositories, and email settings", Scope.SYSTEM),
    TAG("Allows the management of global tag definitions", Scope.SYSTEM),
    VULNERABILITY("Allows the management of custom vulnerabilities", Scope.SYSTEM);
    // @formatter:on

    enum Scope {
        PROJECT, SYSTEM
    }

    private final String description;
    private final Scope scope;

    Permissions(final String description, final Scope scope) {
        this.description = description;
        this.scope = scope;
    }

    public String getDescription() {
        return description;
    }

    public Scope getScope() {
        return scope;
    }

    public boolean isProjectScope() {
        return scope == Scope.PROJECT;
    }

    public boolean isSystemScope() {
        return scope == Scope.SYSTEM;
    }

    public static class Constants {
        public static final String ACCESS_MANAGEMENT = "ACCESS_MANAGEMENT";
        public static final String BADGES_READ = "BADGES_READ";
        public static final String BOM_CREATE = "BOM_CREATE";
        public static final String BOM_READ = "BOM_READ";
        public static final String FINDING_CREATE = "FINDING_CREATE";
        public static final String FINDING_READ = "FINDING_READ";
        public static final String FINDING_UPDATE = "FINDING_UPDATE";
        public static final String NOTIFICATION_RULE = "NOTIFICATION_RULE";
        public static final String POLICY = "POLICY";
        public static final String POLICY_VIOLATION_CREATE = "POLICY_VIOLATION_CREATE";
        public static final String POLICY_VIOLATION_READ = "POLICY_VIOLATION_READ";
        public static final String POLICY_VIOLATION_UPDATE = "POLICY_VIOLATION_UPDATE";
        public static final String PORTFOLIO_ACCESS_CONTROL_BYPASS = "PORTFOLIO_ACCESS_CONTROL_BYPASS";
        public static final String PORTFOLIO = "PORTFOLIO";
        public static final String PROJECT_DELETE = "PROJECT_DELETE";
        public static final String PROJECT_READ = "PROJECT_READ";
        public static final String PROJECT_UPDATE = "PROJECT_UPDATE";
        public static final String SYSTEM_CONFIGURATION = "SYSTEM_CONFIGURATION";
        public static final String TAG = "TAG";
        public static final String VULNERABILITY = "VULNERABILITY";
    }

}
