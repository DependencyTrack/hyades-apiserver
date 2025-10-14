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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.dependencytrack.auth.Permissions;
import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Role;
import org.dependencytrack.persistence.QueryManager;

import alpine.common.logging.Logger;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.Permission;
import alpine.model.Team;
import alpine.security.crypto.DataEncryption;

public class GitLabIntegrationStateChanger extends AbstractIntegrationPoint {

    private static final Logger LOGGER = Logger.getLogger(GitLabIntegrationStateChanger.class);
    private static final String DEFAULT_TEAM = "GitLab Users";
    private final Map<String, Permission> PERMISSIONS_MAP = new HashMap<>();

    @Override
    public String name() {
        return "GitLab Integration State Changer";
    }

    @Override
    public String description() {
        return "Executes GitLab integration enable and disable tasks";
    }

    public void setState(boolean isEnabled) {
        try {
            if (isEnabled) {
                LOGGER.info("Enabling GitLab integration");
                setConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED, "true");
                createGitLabRoles();
                createGitLabDefaultTeam();

                return;
            }

            LOGGER.info("Disabling GitLab integration");
            removeGitLabRoles();
            removeGitLabDefaultTeam();
            setConfigProperty(ConfigPropertyConstants.GITLAB_SBOM_PUSH_ENABLED, "false");
        } catch (RuntimeException ex) {
            LOGGER.error("An error occurred while changing GitLab Integration State", ex);
            handleException(LOGGER, ex);
        }
    }

    private void createGitLabDefaultTeam() {
        try {
            if (qm.getTeam(DEFAULT_TEAM) != null) {
                LOGGER.info("GitLab Users team already exists");
                return;
            }

            final Team team = qm.createTeam(DEFAULT_TEAM, List.of(
                    qm.getPermission(Permissions.Constants.BOM_UPLOAD),
                    qm.getPermission(Permissions.Constants.VIEW_PORTFOLIO)));

            LOGGER.info("Created GitLab default user team");

            final ApiKey apiKey = qm.createApiKey(team);

            setConfigProperty(ConfigPropertyConstants.GITLAB_API_KEY, DataEncryption.encryptAsString(apiKey.getKey()));
        } catch (Exception ex) {
            LOGGER.error("An error occurred while creating GitLab default user team", ex);
            throw new RuntimeException("Failed to create default team for GitLab users", ex);
        }
    }

    private void createGitLabRoles() {
        if (PERMISSIONS_MAP.isEmpty())
            populatePermissionsMap(qm);

        for (GitLabRole role : GitLabRole.values())
            try {
                if (qm.getRoleByName(role.getDescription()) == null) {
                    qm.createRole(role.getDescription(), qm.getPermissionsByName(role.getPermissions()));
                    LOGGER.info("Created GitLab role: " + role.getDescription());
                } else {
                    LOGGER.info("GitLab role already exists: " + role.getDescription());
                }
            } catch (Exception ex) {
                LOGGER.error("An error occurred while creating GitLab roles", ex);
            }
    }

    private void removeGitLabDefaultTeam() {
        try (final QueryManager qm = new QueryManager()) {
            final Team team = qm.getTeam(DEFAULT_TEAM);

            if (team == null) {
                LOGGER.info("GitLab default team does not exist");
                return;
            }

            for (ApiKey key : team.getApiKeys())
                if (key != null) {
                    qm.delete(key);
                    LOGGER.info("Removed API key for GitLab team");
                }

            qm.delete(team);
            LOGGER.info("Removed default GitLab team");

            setConfigProperty(ConfigPropertyConstants.GITLAB_API_KEY, null);
        } catch (Exception ex) {
            LOGGER.error("An error occurred while removing GitLab team", ex);
            throw new RuntimeException("Failed to remove GitLab team", ex);
        }

    }

    private void removeGitLabRoles() {
        try (final QueryManager qm = new QueryManager()) {
            for (GitLabRole role : GitLabRole.values()) {
                Role targetRole = qm.getRoleByName(role.getDescription());
                if (targetRole == null) {
                    LOGGER.info("GitLab role does not exist: " + role.getDescription());
                    continue;
                }

                qm.delete(targetRole);
                LOGGER.info("Removed GitLab role: " + role.getDescription());
            }

        } catch (Exception ex) {
            LOGGER.error("An error occurred while removing GitLab roles", ex);
            throw new RuntimeException("Failed to remove GitLab roles", ex);
        }

    }

    private void populatePermissionsMap(QueryManager qm) {
        // Retrieve all permissions from the database
        List<Permission> allPermissions = Objects.requireNonNullElse(qm.getPermissions(), Collections.emptyList());

        // Add all permissions to the PERMISSIONS_MAP
        for (Permission permission : allPermissions) {
            PERMISSIONS_MAP.put(permission.getName(), permission);
        }
    }

    private void setConfigProperty(ConfigPropertyConstants cpc, String value) {
        final ConfigProperty property = qm.getConfigProperty(cpc.getGroupName(), cpc.getPropertyName());
        property.setPropertyValue(value);

        qm.persist(property);
    }

    public Map<String, Permission> getPermissionsMap() {
        if (PERMISSIONS_MAP.isEmpty()) {
            populatePermissionsMap(qm);
        }
        return PERMISSIONS_MAP;
    }
}
