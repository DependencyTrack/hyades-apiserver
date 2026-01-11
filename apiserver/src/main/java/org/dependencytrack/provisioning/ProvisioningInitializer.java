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
package org.dependencytrack.provisioning;

import alpine.model.Permission;
import alpine.model.Team;
import alpine.model.User;
import alpine.server.auth.PasswordService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.ExtensionPointMetadata;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.config.MutableConfigRegistry;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.runtime.config.RuntimeConfigMapper;
import org.dependencytrack.provisioning.config.ProvisioningConfigLoader;
import org.dependencytrack.provisioning.config.ProvisioningResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.ExtensionConfigResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.SecretResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.TeamResource;
import org.dependencytrack.provisioning.config.ProvisioningResource.UserResource;
import org.dependencytrack.secret.management.SecretAlreadyExistsException;
import org.dependencytrack.secret.management.SecretManager;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.7.0
 */
public final class ProvisioningInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProvisioningInitializer.class);

    private final Config config;

    ProvisioningInitializer(Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public ProvisioningInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        if (!config.getOptionalValue("dt.provisioning.enabled", boolean.class).orElse(false)) {
            LOGGER.info("Provisioning is disabled; Skipping");
            return;
        }

        final ServletContext servletContext = event.getServletContext();

        final var pluginManager = (PluginManager) servletContext.getAttribute(PluginManager.class.getName());
        requireNonNull(pluginManager, "pluginManager has not been initialized");

        final var secretManager = (SecretManager) servletContext.getAttribute(SecretManager.class.getName());
        requireNonNull(secretManager, "secretManager has not been initialized");

        final Path privisioningFilePath = config.getValue("dt.provisioning.file-path", Path.class);

        final List<ProvisioningResource> provisioningResources =
                new ProvisioningConfigLoader(config).load(privisioningFilePath);
        if (provisioningResources.isEmpty()) {
            return;
        }

        // TODO: Add dry-run mode?

        // TODO: Ensure proper ordering, e.g. teams before users.

        for (final ProvisioningResource resource : provisioningResources) {
            switch (resource) {
                case ExtensionConfigResource it -> provisionExtensionConfig(pluginManager, it);
                case SecretResource it -> provisionSecret(secretManager, it);
                case TeamResource it -> provisionTeam(it);
                case UserResource it -> provisionUser(it);
            }
        }
    }

    private void provisionExtensionConfig(
            PluginManager pluginManager,
            ExtensionConfigResource extensionConfigResource) {
        final Class<? extends ExtensionPoint> extensionPointClass =
                pluginManager.getExtensionPoints().stream()
                        .filter(extensionPoint -> extensionPoint.name().equals(extensionConfigResource.extensionPointName()))
                        .map(ExtensionPointMetadata::clazz)
                        .findAny()
                        .orElseThrow(() -> new IllegalStateException(
                                "Extension point %s does not exist".formatted(
                                        extensionConfigResource.extensionPointName())));

        final ExtensionFactory<?> extensionFactory =
                pluginManager.getFactory(extensionPointClass, extensionConfigResource.extensionName());

        final RuntimeConfigSpec configSpec = extensionFactory.runtimeConfigSpec();
        if (configSpec == null) {
            throw new IllegalStateException(
                    "Extension %s/%s does not support runtime configuration".formatted(
                            extensionConfigResource.extensionPointName(), extensionConfigResource.extensionPointName()));
        }

        final var configMapper = RuntimeConfigMapper.getInstance();
        final JsonNode configJsonNode = configMapper.validateJson(extensionConfigResource.config(), configSpec);
        final RuntimeConfig runtimeConfig = configMapper.convert(configJsonNode, configSpec.configClass());

        final MutableConfigRegistry configRegistry =
                pluginManager.getMutableConfigRegistry(
                        extensionPointClass,
                        extensionConfigResource.extensionName());
        configRegistry.setRuntimeConfig(runtimeConfig);

        LOGGER.info(
                "Provisioned config of extension {}/{}",
                extensionConfigResource.extensionPointName(),
                extensionConfigResource.extensionName());
    }

    private void provisionSecret(SecretManager secretManager, SecretResource secretResource) {
        try {
            secretManager.createSecret(secretResource.name(), secretResource.description(), secretResource.value());
            LOGGER.info("Provisioned secret {}", secretResource.name());
        } catch (SecretAlreadyExistsException e) {
            LOGGER.info("Secret {} already exists", secretResource.name());
        }
    }

    private void provisionTeam(TeamResource teamResource) {
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                Team team = qm.getTeam(teamResource.name());
                if (team != null) {
                    LOGGER.info("Team {} already exists", teamResource.name());
                    return;
                }

                team = new Team();
                team.setName(teamResource.name());
                qm.persist(team);

                if (teamResource.permissionNames() == null || teamResource.permissionNames().isEmpty()) {
                    return;
                }

                for (final String permissionName : teamResource.permissionNames()) {
                    final Permission permission = qm.getPermission(permissionName);
                    if (permission == null) {
                        throw new IllegalStateException("Permission %s does not exist".formatted(permissionName));
                    }

                    team.getPermissions().add(permission);
                }
            });
        }

        LOGGER.info("Provisioned team {}", teamResource.name());
    }

    private void provisionUser(UserResource userResource) {
        try (final var qm = new QueryManager()) {
            qm.runInTransaction(() -> {
                User user = qm.getManagedUser(userResource.name());
                if (user != null) {
                    LOGGER.info("User {} already exists", userResource.name());
                    return;
                }

                user = qm.createManagedUser(
                        userResource.name(),
                        null,
                        userResource.email(),
                        String.valueOf(PasswordService.createHash(userResource.password().toCharArray())),
                        false,
                        false,
                        false);

                if (userResource.teamNames() == null || userResource.teamNames().isEmpty()) {
                    return;
                }

                for (final String teamName : userResource.teamNames()) {
                    final Team team = qm.getTeam(teamName);
                    if (team == null) {
                        throw new IllegalStateException("Team %s does not exist".formatted(teamName));
                    }

                    qm.addUserToTeam(user, team);
                }
            });
        }

        LOGGER.info("Provisioned user {}", userResource.name());
    }

}
