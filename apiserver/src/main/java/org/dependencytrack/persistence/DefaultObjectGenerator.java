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
package org.dependencytrack.persistence;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import alpine.model.ManagedUser;
import alpine.model.Permission;
import alpine.server.auth.PasswordService;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.License;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.parser.spdx.json.SpdxLicenseDetailParser;
import org.dependencytrack.persistence.defaults.DefaultLicenseGroupImporter;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.WaitingLockConfiguration;

import java.io.IOException;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_DEFAULT_OBJECTS_VERSION;
import static org.dependencytrack.util.LockProvider.executeWithLockWaiting;

/**
 * Creates default objects on an empty database.
 *
 * @author Steve Springett
 * @since 3.0.0
 */
public class DefaultObjectGenerator implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(DefaultObjectGenerator.class);
    private static final Map<String, Permission> PERMISSIONS_MAP = new HashMap<>();

    private static final Map<String, List<String>> DEFAULT_TEAM_PERMISSIONS = Map.of(
            "Administrators", Stream.of(Permissions.values())
                    .map(Permissions::name)
                    .toList(),
            "Portfolio Managers", List.of(
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_READ,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE),
            "Automation", List.of(
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.BOM_UPLOAD),
            "Badge Viewers", List.of(
                    Permissions.Constants.VIEW_BADGES));

    private static final Map<String, List<String>> DEFAULT_ROLE_PERMISSIONS = Map.of(
            "Project Admin", List.of(
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_READ,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE,
                    Permissions.Constants.VULNERABILITY_ANALYSIS,
                    Permissions.Constants.VULNERABILITY_ANALYSIS_CREATE,
                    Permissions.Constants.VULNERABILITY_ANALYSIS_READ,
                    Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE,
                    Permissions.Constants.POLICY_MANAGEMENT,
                    Permissions.Constants.POLICY_MANAGEMENT_CREATE,
                    Permissions.Constants.POLICY_MANAGEMENT_READ,
                    Permissions.Constants.POLICY_MANAGEMENT_UPDATE,
                    Permissions.Constants.POLICY_MANAGEMENT_DELETE),
            "Project Auditor", List.of(
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.VIEW_VULNERABILITY,
                    Permissions.Constants.VIEW_POLICY_VIOLATION,
                    Permissions.Constants.VULNERABILITY_ANALYSIS_READ),
            "Project Editor", List.of(
                    Permissions.Constants.BOM_UPLOAD,
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.PORTFOLIO_MANAGEMENT_READ,
                    Permissions.Constants.VIEW_VULNERABILITY,
                    Permissions.Constants.VULNERABILITY_ANALYSIS_READ,
                    Permissions.Constants.PROJECT_CREATION_UPLOAD),
            "Project Viewer", List.of(
                    Permissions.Constants.VIEW_PORTFOLIO,
                    Permissions.Constants.VIEW_VULNERABILITY,
                    Permissions.Constants.VIEW_BADGES));

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.INIT_TASKS_ENABLED)) {
            LOGGER.info("Not populating database with default objects because %s is disabled"
                    .formatted(ConfigKey.INIT_TASKS_ENABLED.getPropertyName()));
            return;
        }

        // Ensure that this task is only executed by a single instance at once.
        // Wait for lock acquisition rather than simply skipping execution,
        // since application logic may depend on default objects being present.
        final var lockConfig = new WaitingLockConfiguration(
                /* createdAt */ Instant.now(),
                /* name */ getClass().getName(),
                /* lockAtMostFor */ Duration.ofMinutes(5),
                /* lockAtLeastFor */ Duration.ZERO,
                /* pollInterval */ Duration.ofSeconds(1),
                /* waitTimeout */ Duration.ofMinutes(5));

        try {
            executeWithLockWaiting(lockConfig, this::executeLocked);
        } catch (Throwable t) {
            if (Config.getInstance().getPropertyAsBoolean(ConfigKey.INIT_AND_EXIT)) {
                // Make absolutely sure that we exit with non-zero code so
                // the container orchestrator knows to restart the container.
                LOGGER.error("Failed to populate database with default objects", t);
                System.exit(1);
            }

            throw new RuntimeException("Failed to populate database with default objects", t);
        }

        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.INIT_AND_EXIT)) {
            LOGGER.info("Exiting because %s is enabled".formatted(ConfigKey.INIT_AND_EXIT.getPropertyName()));
            System.exit(0);
        }
    }

    private void executeLocked() {
        assertLocked();

        if (!shouldExecute()) {
            LOGGER.info("Default objects already populated for build %s (timestamp: %s); Skipping".formatted(
                    Config.getInstance().getApplicationBuildUuid(),
                    Config.getInstance().getApplicationBuildTimestamp()));
            return;
        }

        // TODO: Make population transactional with recordDefaultObjectsVersion().

        LOGGER.info("Initializing default object generator");
        try (final var qm = new QueryManager()) {
            loadDefaultPermissions(qm);
            loadDefaultPersonas(qm);
            loadDefaultLicenses(qm);
            loadDefaultLicenseGroups(qm);
            loadDefaultRepositories(qm);
            loadDefaultRoles(qm);
            loadDefaultConfigProperties(qm);
            loadDefaultNotificationPublishers(qm);
            recordDefaultObjectsVersion(qm);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        /* Intentionally blank to satisfy interface */
    }

    private boolean shouldExecute() {
        try (final var qm = new QueryManager()) {
            final ConfigProperty configProperty = qm.getConfigProperty(
                    INTERNAL_DEFAULT_OBJECTS_VERSION.getGroupName(),
                    INTERNAL_DEFAULT_OBJECTS_VERSION.getPropertyName());

            return configProperty == null
                    || configProperty.getPropertyValue() == null
                    || !Config.getInstance().getApplicationBuildUuid().equals(configProperty.getPropertyValue());
        }
    }

    private void recordDefaultObjectsVersion(final QueryManager qm) {
        qm.runInTransaction(() -> {
            final ConfigProperty configProperty = qm.getConfigProperty(
                    INTERNAL_DEFAULT_OBJECTS_VERSION.getGroupName(),
                    INTERNAL_DEFAULT_OBJECTS_VERSION.getPropertyName());

            configProperty.setPropertyValue(Config.getInstance().getApplicationBuildUuid());
        });
    }

    public static void loadDefaultLicenses() {
        try (final var qm = new QueryManager()) {
            loadDefaultLicenses(qm);
        }
    }

    /**
     * Loads the default licenses into the database if no license data exists.
     */
    private static void loadDefaultLicenses(final QueryManager qm) {
        LOGGER.info("Synchronizing SPDX license definitions to datastore");

        final SpdxLicenseDetailParser parser = new SpdxLicenseDetailParser();
        try {
            final List<License> licenses = parser.getLicenseDefinitions();
            for (final License license : licenses) {
                LOGGER.debug("Synchronizing: " + license.getName());
                qm.synchronizeLicense(license, false);
            }
        } catch (IOException e) {
            LOGGER.error("An error occurred during the parsing SPDX license definitions");
            LOGGER.error(e.getMessage());
        }
    }

    /**
     * Loads the default license groups into the database if no license groups exists.
     */
    private void loadDefaultLicenseGroups(final QueryManager qm) {
        final DefaultLicenseGroupImporter importer = new DefaultLicenseGroupImporter(qm);
        if (!importer.shouldImport()) {
            return;
        }
        LOGGER.info("Adding default license group definitions to datastore");
        try {
            importer.loadDefaults();
        } catch (IOException e) {
            LOGGER.error("An error occurred loading default license group definitions");
            LOGGER.error(e.getMessage());
        }
    }

    public void loadDefaultPermissions() {
        try (final var qm = new QueryManager()) {
            loadDefaultPermissions(qm);
        }
    }

    /**
     * Loads the default permissions
     */
    private void loadDefaultPermissions(final QueryManager qm) {
        LOGGER.info("Synchronizing permissions to datastore");

        List<String> existing = Objects.requireNonNullElse(qm.getPermissions(), Collections.<Permission>emptyList())
                .stream()
                .map(Permission::getName)
                .toList();

        for (final Permissions value : Permissions.values())
            if (!existing.contains(value.name())) {
                LOGGER.debug("Creating permission: " + value.name());
                PERMISSIONS_MAP.put(value.name(), qm.createPermission(value.name(), value.getDescription()));
            }
    }

    @SuppressWarnings("unused")
    private void loadDefaultPersonas() {
        try (final var qm = new QueryManager()) {
            loadDefaultPersonas(qm);
        }
    }

    /**
     * Loads the default users and teams
     */
    private void loadDefaultPersonas(final QueryManager qm) {
        if (!qm.getManagedUsers().isEmpty() && !qm.getTeams().isEmpty())
            return;

        LOGGER.info("Adding default users and teams to datastore");

        LOGGER.debug("Creating user: admin");
        ManagedUser admin = qm.createManagedUser("admin", "Administrator", "admin@localhost",
                new String(PasswordService.createHash("admin".toCharArray())), true, true, false);

        for (var name : new String[] { "Administrators", "Portfolio Managers", "Automation", "Badge Viewers" }) {
            LOGGER.debug("Creating team: " + name);
            var team = qm.createTeam(name);

            LOGGER.debug("Assigning default permissions for team: " + name);
            team.setPermissions(getPermissionsByName(DEFAULT_TEAM_PERMISSIONS.get(name)));

            qm.persist(team);
        }

        LOGGER.debug("Adding admin user to System Administrators");
        qm.addUserToTeam(admin, qm.getTeam("Administrators"));

        admin = qm.getObjectById(ManagedUser.class, admin.getId());
        admin.setPermissions(qm.getPermissions());
        qm.persist(admin);
    }

    /**
     * Perform a lookup of {@link Permission}s for specified name(s).
     *
     * @param names permission names
     * @return list of {@link Permission}s
     */
    private List<Permission> getPermissionsByName(List<String> names) {
        return names.stream().map(PERMISSIONS_MAP::get).filter(Objects::nonNull).toList();
    }

    /**
     * Loads the default Roles
     */
    private void loadDefaultRoles(final QueryManager qm) {
        if (!qm.getRoles().isEmpty())
            return;

        LOGGER.info("Adding default roles to datastore");

        for (var name : new String[] { "Project Admin", "Project Auditor", "Project Editor", "Project Viewer" }) {
            LOGGER.debug("Creating role: " + name);
            qm.createRole(name, getPermissionsByName(DEFAULT_ROLE_PERMISSIONS.get(name)));
        }
    }

    public void loadDefaultRepositories() {
        try (final var qm = new QueryManager()) {
            loadDefaultRepositories(qm);
        }
    }

    /**
    * Loads the default repositories
    */
    private void loadDefaultRepositories(final QueryManager qm) {
        LOGGER.info("Synchronizing default repositories to datastore");
        // @formatter:off
        qm.createRepository(RepositoryType.CPAN, "cpan-public-registry", "https://fastapi.metacpan.org/v1/", true, false, false, null, null);
        qm.createRepository(RepositoryType.GEM, "rubygems.org", "https://rubygems.org/", true, false, false,null, null);
        qm.createRepository(RepositoryType.HEX, "hex.pm", "https://hex.pm/", true, false, false, null, null);
        qm.createRepository(RepositoryType.MAVEN, "central", "https://repo1.maven.org/maven2/", true, false, false, null, null);
        qm.createRepository(RepositoryType.MAVEN, "atlassian-public", "https://packages.atlassian.com/content/repositories/atlassian-public/", true, false, false, null, null);
        qm.createRepository(RepositoryType.MAVEN, "jboss-releases", "https://repository.jboss.org/nexus/content/repositories/releases/", true, false, false, null, null);
        qm.createRepository(RepositoryType.MAVEN, "clojars", "https://repo.clojars.org/", true, false, false, null, null);
        qm.createRepository(RepositoryType.MAVEN, "google-android", "https://maven.google.com/", true, false, false, null, null);
        qm.createRepository(RepositoryType.NPM, "npm-public-registry", "https://registry.npmjs.org/", true, false, false, null, null);
        qm.createRepository(RepositoryType.PYPI, "pypi.org", "https://pypi.org/", true, false, false, null, null);
        qm.createRepository(RepositoryType.NUGET, "nuget-gallery", "https://api.nuget.org/", true, false, false, null, null);
        qm.createRepository(RepositoryType.COMPOSER, "packagist", "https://repo.packagist.org/", true, false, false, null, null);
        qm.createRepository(RepositoryType.CARGO, "crates.io", "https://crates.io", true, false, false, null, null);
        qm.createRepository(RepositoryType.GO_MODULES, "proxy.golang.org", "https://proxy.golang.org", true, false, false, null, null);
        qm.createRepository(RepositoryType.GITHUB, "github.com", "https://github.com", true, false, false, null, null);
        qm.createRepository(RepositoryType.HACKAGE, "hackage.haskell", "https://hackage.haskell.org/", true, false, false, null, null);
        qm.createRepository(RepositoryType.NIXPKGS, "nixos.org", "https://channels.nixos.org/nixpkgs-unstable/packages.json.br", true, false, false, null, null);
        // @formatter:on
    }

    @SuppressWarnings("unused")
    private void loadDefaultConfigProperties() {
        try (final var qm = new QueryManager()) {
            loadDefaultConfigProperties(qm);
        }
    }

    /**
     * Loads the default ConfigProperty objects
     */
    private void loadDefaultConfigProperties(final QueryManager qm) {
        LOGGER.info("Synchronizing config properties to datastore");
        for (final ConfigPropertyConstants cpc : ConfigPropertyConstants.values()) {
            LOGGER.debug("Creating config property: " + cpc.getGroupName() + " / " + cpc.getPropertyName());
            if (qm.getConfigProperty(cpc.getGroupName(), cpc.getPropertyName()) == null) {
                qm.createConfigProperty(cpc.getGroupName(), cpc.getPropertyName(), cpc.getDefaultPropertyValue(),
                        cpc.getPropertyType(), cpc.getDescription());
            }
        }
    }

    public void loadDefaultNotificationPublishers() {
        try (final var qm = new QueryManager()) {
            loadDefaultNotificationPublishers(qm);
        }
    }

    /**
     * Loads the default notification publishers
     */
    private void loadDefaultNotificationPublishers(final QueryManager qm) {
        LOGGER.info("Synchronizing notification publishers to datastore");
        try {
            NotificationUtil.loadDefaultNotificationPublishers(qm);
        } catch (IOException e) {
            LOGGER.error("An error occurred while synchronizing a default notification publisher", e);
        }
    }
}
