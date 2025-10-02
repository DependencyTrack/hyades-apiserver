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

import alpine.model.IConfigProperty;
import alpine.model.IConfigProperty.PropertyType;
import org.apache.commons.lang3.SystemUtils;

import java.util.Arrays;
import java.util.UUID;

public enum ConfigPropertyConstants {

    INTERNAL_CLUSTER_ID("internal", "cluster.id", UUID.randomUUID().toString(), PropertyType.STRING, "Unique identifier of the cluster", ConfigPropertyAccessMode.READ_ONLY),
    INTERNAL_DEFAULT_OBJECTS_VERSION("internal", "default.objects.version", null, PropertyType.STRING, "Version of the default objects in the database", ConfigPropertyAccessMode.READ_ONLY),
    GENERAL_BASE_URL("general", "base.url", null, PropertyType.URL, "URL used to construct links back to Dependency-Track from external systems", ConfigPropertyAccessMode.READ_WRITE),
    GENERAL_BADGE_ENABLED("general", "badge.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable unauthenticated access to SVG badge from metrics", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_ENABLED("email", "smtp.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable SMTP", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_FROM_ADDR("email", "smtp.from.address", null, PropertyType.STRING, "The from email address to use to send output SMTP mail", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_SERVER_HOSTNAME("email", "smtp.server.hostname", null, PropertyType.STRING, "The hostname or IP address of the SMTP mail server", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_SERVER_PORT("email", "smtp.server.port", null, PropertyType.INTEGER, "The port the SMTP server listens on", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_USERNAME("email", "smtp.username", null, PropertyType.STRING, "The optional username to authenticate with when sending outbound SMTP mail", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_PASSWORD("email", "smtp.password", null, PropertyType.ENCRYPTEDSTRING, "The optional password for the username used for authentication", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_SSLTLS("email", "smtp.ssltls", "false", PropertyType.BOOLEAN, "Flag to enable/disable the use of SSL/TLS when connecting to the SMTP server", ConfigPropertyAccessMode.READ_WRITE),
    EMAIL_SMTP_TRUSTCERT("email", "smtp.trustcert", "false", PropertyType.BOOLEAN, "Flag to enable/disable the trust of the certificate presented by the SMTP server", ConfigPropertyAccessMode.READ_WRITE),
    INTERNAL_COMPONENTS_GROUPS_REGEX("internal-components", "groups.regex", null, PropertyType.STRING, "Regex that matches groups of internal components", ConfigPropertyAccessMode.READ_WRITE),
    INTERNAL_COMPONENTS_NAMES_REGEX("internal-components", "names.regex", null, PropertyType.STRING, "Regex that matches names of internal components", ConfigPropertyAccessMode.READ_WRITE),
    JIRA_URL("integrations", "jira.url", null, PropertyType.URL, "The base URL of the JIRA instance", ConfigPropertyAccessMode.READ_WRITE),
    JIRA_USERNAME("integrations", "jira.username", null, PropertyType.STRING, "The optional username to authenticate with when creating an Jira issue", ConfigPropertyAccessMode.READ_WRITE),
    JIRA_PASSWORD("integrations", "jira.password", null, PropertyType.ENCRYPTEDSTRING, "The optional password for the username used for authentication", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_METRICS_RETENTION_DAYS("maintenance", "metrics.retention.days", "90", PropertyType.INTEGER, "Number of days to retain metrics data for", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_PROJECTS_RETENTION_DAYS("maintenance", "projects.retention.days", "30", PropertyType.INTEGER, "Number of days to retain inactive projects for", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_PROJECTS_RETENTION_TYPE("maintenance", "projects.retention.type", null, PropertyType.STRING, "Retention policy type for inactive projects", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_PROJECTS_RETENTION_VERSIONS("maintenance", "projects.retention.versions", "2", PropertyType.INTEGER, "Number of last inactive projects to retain and delete rest", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_TAGS_DELETE_UNUSED("maintenance", "tags.delete.unused", "true", PropertyType.BOOLEAN, "Whether unused tags shall be deleted", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_VULNERABILITY_SCAN_RETENTION_HOURS("maintenance", "vuln.scan.retention.hours", "24", PropertyType.INTEGER, "Number of hours to retain vulnerability scan records for", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_WORKFLOW_RETENTION_HOURS("maintenance", "workflow.retention.hours", "72", PropertyType.INTEGER, "Number of hours to retain workflow records for", ConfigPropertyAccessMode.READ_WRITE),
    MAINTENANCE_WORKFLOW_STEP_TIMEOUT_MINUTES("maintenance", "workflow.step.timeout.minutes", "60", PropertyType.INTEGER, "Number of minutes after which workflow steps are timed out", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_INTERNAL_ENABLED("scanner", "internal.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable the internal analyzer", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_INTERNAL_FUZZY_ENABLED("scanner", "internal.fuzzy.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable non-exact fuzzy matching using the internal analyzer", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL("scanner", "internal.fuzzy.exclude.purl", "true", PropertyType.BOOLEAN, "Flag to enable/disable fuzzy matching on components that have a Package URL (PURL) defined", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_INTERNAL_FUZZY_EXCLUDE_INTERNAL("scanner", "internal.fuzzy.exclude.internal", "true", PropertyType.BOOLEAN, "Flag to enable/disable fuzzy matching on components that are marked internal.", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_NPMAUDIT_ENABLED("scanner", "npmaudit.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable NPM Audit", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_OSSINDEX_ENABLED("scanner", "ossindex.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable Sonatype OSS Index", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_OSSINDEX_API_USERNAME("scanner", "ossindex.api.username", null, PropertyType.STRING, "The API username used for OSS Index authentication", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_OSSINDEX_API_TOKEN("scanner", "ossindex.api.token", null, PropertyType.ENCRYPTEDSTRING, "The API token used for OSS Index authentication", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_SNYK_ENABLED("scanner", "snyk.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable Snyk Vulnerability Analysis", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_SNYK_API_TOKEN("scanner", "snyk.api.token", null, PropertyType.ENCRYPTEDSTRING, "The API token used for Snyk API authentication", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_SNYK_ORG_ID("scanner", "snyk.org.id", null, PropertyType.STRING, "The Organization ID used for Snyk API access", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_SNYK_API_VERSION("scanner", "snyk.api.version", "2022-11-14", PropertyType.STRING, "Snyk API version", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_SNYK_CVSS_SOURCE("scanner", "snyk.cvss.source", "NVD", PropertyType.STRING, "Type of source to be prioritized for cvss calculation", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_SNYK_BASE_URL("scanner", "snyk.base.url", "https://api.snyk.io", PropertyType.URL, "Base Url pointing to the hostname and path for Snyk analysis", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_CSAF_ENABLED("scanner", "csaf.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable CSAF Vulnerability Analysis", ConfigPropertyAccessMode.READ_WRITE),
    SCANNER_CSAF_THRESHOLD("scanner", "csaf.threshold", "80", PropertyType.INTEGER, "Matching threshold for CSAF Vulnerability Analysis", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_POLICY_FILE_LAST_MODIFIED_HASH("vulnerability-policy", "vulnerability.policy.file.last.modified.hash", null,  PropertyType.STRING, "Hash value or etag of the last fetched bundle if any", ConfigPropertyAccessMode.READ_ONLY),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED("vuln-source", "github.advisories.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable GitHub Advisories", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ALIAS_SYNC_ENABLED("vuln-source", "github.advisories.alias.sync.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable alias synchronization for GitHub Advisories", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ACCESS_TOKEN("vuln-source", "github.advisories.access.token", null, PropertyType.STRING, "The access token used for GitHub API authentication", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL("vuln-source", "google.osv.base.url", "https://osv-vulnerabilities.storage.googleapis.com/", PropertyType.URL, "A base URL pointing to the hostname and path for OSV mirroring", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED("vuln-source", "google.osv.enabled", null, PropertyType.STRING, "List of enabled ecosystems to mirror OSV", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED("vuln-source", "google.osv.alias.sync.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable alias synchronization for OSV", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_EPSS_ENABLED("vuln-source", "epss.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable Exploit Prediction Scoring System", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_EPSS_FEEDS_URL("vuln-source", "epss.feeds.url", "https://epss.cyentia.com", PropertyType.URL, "A base URL pointing to the hostname and path of the EPSS feeds", ConfigPropertyAccessMode.READ_WRITE),
    VULNERABILITY_SOURCE_CSAF_ENABLED("vuln-source", "csaf.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable CSAF Vulnerability sources", ConfigPropertyAccessMode.READ_WRITE),
    ACCEPT_ARTIFACT_CYCLONEDX("artifact", "cyclonedx.enabled", "true", PropertyType.BOOLEAN, "Flag to enable/disable the systems ability to accept CycloneDX uploads", ConfigPropertyAccessMode.READ_WRITE),
    BOM_VALIDATION_MODE("artifact", "bom.validation.mode", BomValidationMode.ENABLED.name(), PropertyType.STRING, "Flag to control the BOM validation mode", ConfigPropertyAccessMode.READ_WRITE),
    BOM_VALIDATION_TAGS_INCLUSIVE("artifact", "bom.validation.tags.inclusive", "[]", PropertyType.STRING, "JSON array of tags for which BOM validation shall be performed", ConfigPropertyAccessMode.READ_WRITE),
    BOM_VALIDATION_TAGS_EXCLUSIVE("artifact", "bom.validation.tags.exclusive", "[]", PropertyType.STRING, "JSON array of tags for which BOM validation shall NOT be performed", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_ENABLED("integrations", "fortify.ssc.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Fortify SSC integration", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_SYNC_CADENCE("integrations", "fortify.ssc.sync.cadence", "60", PropertyType.INTEGER, "The cadence (in minutes) to upload to Fortify SSC", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_URL("integrations", "fortify.ssc.url", null, PropertyType.URL, "Base URL to Fortify SSC", ConfigPropertyAccessMode.READ_WRITE),
    FORTIFY_SSC_TOKEN("integrations", "fortify.ssc.token", null, PropertyType.ENCRYPTEDSTRING, "The token to use to authenticate to Fortify SSC", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_ENABLED("integrations", "defectdojo.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable DefectDojo integration", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_REIMPORT_ENABLED("integrations", "defectdojo.reimport.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable DefectDojo reimport-scan API endpoint", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_SYNC_CADENCE("integrations", "defectdojo.sync.cadence", "60", PropertyType.INTEGER, "The cadence (in minutes) to upload to DefectDojo", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_URL("integrations", "defectdojo.url", null, PropertyType.URL, "Base URL to DefectDojo", ConfigPropertyAccessMode.READ_WRITE),
    DEFECTDOJO_API_KEY("integrations", "defectdojo.apiKey", null, PropertyType.STRING, "API Key for DefectDojo", ConfigPropertyAccessMode.READ_WRITE),
    KENNA_ENABLED("integrations", "kenna.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable Kenna Security integration", ConfigPropertyAccessMode.READ_WRITE),
    KENNA_SYNC_CADENCE("integrations", "kenna.sync.cadence", "60", PropertyType.INTEGER, "The cadence (in minutes) to upload to Kenna Security", ConfigPropertyAccessMode.READ_WRITE),
    KENNA_TOKEN("integrations", "kenna.token", null, PropertyType.ENCRYPTEDSTRING, "The token to use when authenticating to Kenna Security", ConfigPropertyAccessMode.READ_WRITE),
    KENNA_CONNECTOR_ID("integrations", "kenna.connector.id", null, PropertyType.STRING, "The Kenna Security connector identifier to upload to", ConfigPropertyAccessMode.READ_WRITE),
    ACCESS_MANAGEMENT_ACL_ENABLED("access-management", "acl.enabled", "false", PropertyType.BOOLEAN, "Flag to enable/disable access control to projects in the portfolio", ConfigPropertyAccessMode.READ_WRITE, true),
    NOTIFICATION_TEMPLATE_BASE_DIR("notification", "template.baseDir", SystemUtils.getEnvironmentVariable("DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY", System.getProperty("user.home")), PropertyType.STRING, "The base directory to use when searching for notification templates", ConfigPropertyAccessMode.READ_WRITE),
    NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED("notification", "template.default.override.enabled", SystemUtils.getEnvironmentVariable("DEFAULT_TEMPLATES_OVERRIDE_ENABLED", "false"), PropertyType.BOOLEAN, "Flag to enable/disable override of default notification templates", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_LDAP_SYNC_CADENCE("task-scheduler", "ldap.sync.cadence", "6", PropertyType.INTEGER, "Sync cadence (in hours) for LDAP", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_GHSA_MIRROR_CADENCE("task-scheduler", "ghsa.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for Github Security Advisories", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_OSV_MIRROR_CADENCE("task-scheduler", "osv.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for OSV database", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_CSAF_MIRROR_CADENCE("task-scheduler", "csaf.mirror.cadence", "1", PropertyType.INTEGER, "Mirror cadence (in hours) for CSAF Advisories", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_NIST_MIRROR_CADENCE("task-scheduler", "nist.mirror.cadence", "24", PropertyType.INTEGER, "Mirror cadence (in hours) for NVD database", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_PORTFOLIO_METRICS_UPDATE_CADENCE("task-scheduler", "portfolio.metrics.update.cadence", "1", PropertyType.INTEGER, "Update cadence (in hours) for portfolio metrics", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_VULNERABILITY_METRICS_UPDATE_CADENCE("task-scheduler", "vulnerability.metrics.update.cadence", "1", PropertyType.INTEGER, "Update cadence (in hours) for vulnerability metrics", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_PORTFOLIO_VULNERABILITY_ANALYSIS_CADENCE("task-scheduler", "portfolio.vulnerability.analysis.cadence", "24", PropertyType.INTEGER, "Launch cadence (in hours) for portfolio vulnerability analysis", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_REPOSITORY_METADATA_FETCH_CADENCE("task-scheduler", "repository.metadata.fetch.cadence", "24", PropertyType.INTEGER, "Metadada fetch cadence (in hours) for package repositories", ConfigPropertyAccessMode.READ_WRITE),
    TASK_SCHEDULER_INTERNAL_COMPONENT_IDENTIFICATION_CADENCE("task-scheduler", "internal.components.identification.cadence", "6", PropertyType.INTEGER, "Internal component identification cadence (in hours)", ConfigPropertyAccessMode.READ_WRITE),
    SEARCH_INDEXES_CONSISTENCY_CHECK_ENABLED("search-indexes", "consistency.check.enabled", "true", PropertyType.BOOLEAN, "Flag to enable lucene indexes periodic consistency check", ConfigPropertyAccessMode.READ_WRITE),
    SEARCH_INDEXES_CONSISTENCY_CHECK_CADENCE("search-indexes", "consistency.check.cadence", "4320", PropertyType.INTEGER, "Lucene indexes consistency check cadence (in minutes)", ConfigPropertyAccessMode.READ_WRITE),
    SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD("search-indexes", "consistency.check.delta.threshold", "20", PropertyType.INTEGER, "Threshold used to trigger an index rebuild when comparing database table and corresponding lucene index (in percentage). It must be an integer between 1 and 100", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_HISTORY_ENABLED("risk-score", "weight.history.enabled", "true", PropertyType.BOOLEAN, "Flag to re-calculate risk score history", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_CRITICAL("risk-score", "weight.critical", "10", PropertyType.INTEGER, "Critical severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_HIGH("risk-score", "weight.high", "5", PropertyType.INTEGER, "High severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_MEDIUM("risk-score", "weight.medium", "3", PropertyType.INTEGER, "Medium severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_LOW("risk-score", "weight.low", "1", PropertyType.INTEGER, "Low severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    CUSTOM_RISK_SCORE_UNASSIGNED("risk-score", "weight.unassigned", "5", PropertyType.INTEGER, "Unassigned severity vulnerability weight (between 1-10)", ConfigPropertyAccessMode.READ_WRITE),
    WELCOME_MESSAGE("general", "welcome.message.html", "%3Chtml%3E%3Ch1%3EYour%20Welcome%20Message%3C%2Fh1%3E%3C%2Fhtml%3E", PropertyType.STRING, "Custom HTML Code that is displayed before login", ConfigPropertyAccessMode.READ_WRITE, true),
    IS_WELCOME_MESSAGE("general", "welcome.message.enabled", "false", PropertyType.BOOLEAN, "Bool that says whether to show the welcome message or not", ConfigPropertyAccessMode.READ_WRITE, true),
    DEFAULT_LANGUAGE("general", "default.locale", null, PropertyType.STRING, "Determine the default Language to use", ConfigPropertyAccessMode.READ_WRITE, true);

    private final String groupName;
    private final String propertyName;
    private final String defaultPropertyValue;
    private final PropertyType propertyType;
    private final String description;
    private final ConfigPropertyAccessMode accessMode;
    private final Boolean isPublic;

    ConfigPropertyConstants(final String groupName,
                            final String propertyName,
                            final String defaultPropertyValue,
                            final PropertyType propertyType,
                            final String description,
                            final ConfigPropertyAccessMode accessMode) {
        this.groupName = groupName;
        this.propertyName = propertyName;
        this.defaultPropertyValue = defaultPropertyValue;
        this.propertyType = propertyType;
        this.description = description;
        this.accessMode = accessMode;
        this.isPublic = false;
    }

    ConfigPropertyConstants(final String groupName,
                            final String propertyName,
                            final String defaultPropertyValue,
                            final PropertyType propertyType,
                            final String description,
                            final ConfigPropertyAccessMode accessMode,
                            final Boolean isPublic) {
        this.groupName = groupName;
        this.propertyName = propertyName;
        this.defaultPropertyValue = defaultPropertyValue;
        this.propertyType = propertyType;
        this.description = description;
        this.accessMode = accessMode;
        this.isPublic = isPublic;
    }

    public static ConfigPropertyConstants ofProperty(final IConfigProperty property) {
        return Arrays.stream(values())
                .filter(value -> value.groupName.equals(property.getGroupName())
                        && value.propertyName.equals(property.getPropertyName()))
                .findFirst()
                .orElse(null);
    }

    public String getGroupName() {
        return groupName;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public String getDefaultPropertyValue() {
        return defaultPropertyValue;
    }

    public PropertyType getPropertyType() {
        return propertyType;
    }

    public String getDescription() {
        return description;
    }

    public ConfigPropertyAccessMode getAccessMode() {
        return accessMode;
    }

    public Boolean getIsPublic() {
        return isPublic;
    }
}
