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

import static org.dependencytrack.model.ConfigPropertyConstants.GITLAB_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.dependencytrack.integrations.AbstractIntegrationPoint;
import org.dependencytrack.model.Role;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.RoleDao;
import org.jdbi.v3.core.Handle;

import alpine.common.logging.Logger;
import alpine.model.Permission;

public class GitLabIntegrationStateChanger extends AbstractIntegrationPoint {

    private static final Logger LOGGER = Logger.getLogger(GitLabIntegrationStateChanger.class);
    private static final String INTEGRATIONS_GROUP = GITLAB_ENABLED.getGroupName();
    private final Map<String, Permission> PERMISSIONS_MAP = new HashMap<>();

    public GitLabIntegrationStateChanger() {
    }

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
                createGitLabRoles();
                LOGGER.info("GitLab integration enabled");
            } else {
                LOGGER.info("Disabling GitLab integration");
                removeGitlabRoles();
                LOGGER.info("GitLab integration disabled");
            }

        } catch (RuntimeException ex) {
            LOGGER.error("An error occurred while changing Gitlab Integration State", ex);
            handleException(LOGGER, ex);
        }
    }

    private void createGitLabRoles() {
        if (PERMISSIONS_MAP.isEmpty()) {
            populatePermissionsMap(qm);
        }

        for (GitLabRole role : GitLabRole.values()) {
            try {
                if (qm.getRoleByName(role.getDescription()) == null) {
                    qm.createRole(role.getDescription(), qm.getPermissionsByName(role.getPermissions().toArray(String[]::new)));
                    LOGGER.info("Created GitLab role: " + role.getDescription());
                } else {
                    LOGGER.info("GitLab role already exists: " + role.getDescription());
                }
            } catch (Exception ex) {
                LOGGER.error("An error occurred while creating GitLab roles", ex);
                throw new RuntimeException("Failed to create GitLab roles", ex);
            }
        }
    }

    private void removeGitlabRoles() {
        try (Handle jdbiHandle = openJdbiHandle()) {
            for (GitLabRole role : GitLabRole.values()) {
                Role targetRole = qm.getRoleByName(role.getDescription());
                if (targetRole == null) {
                    LOGGER.info("GitLab role does not exist: " + role.getDescription());
                    continue;
                }

                jdbiHandle.attach(RoleDao.class).deleteRole(targetRole.getId());
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

    private List<Permission> getPermissionsByName(List<String> names) {
        return names.stream().map(PERMISSIONS_MAP::get).filter(Objects::nonNull).toList();
    }
}
