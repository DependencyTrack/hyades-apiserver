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

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;
import alpine.model.Permission;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Embedded;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;

/**
 * Model for maintaining user permissions on a given project.
 *
 * @author Jonathan Howard
 * @since 5.6.0
 */
@PersistenceCapable(table = "USER_PROJECT_EFFECTIVE_PERMISSIONS")
@Index(name = "USER_PROJECT_EFFECTIVE_PERMISSIONS_LDAPUSERS_IDX", unique = "true", members = { "project", "role", "ldapUser" })
@Index(name = "USER_PROJECT_EFFECTIVE_PERMISSIONS_MANAGEDUSERS_IDX", unique = "true", members = { "project", "role", "managedUser" })
@Index(name = "USER_PROJECT_EFFECTIVE_PERMISSIONS_OIDCUSERS_IDX", unique = "true", members = { "project", "role", "oidcUser" })
@FetchGroup(name = "ALL", members = {
        @Persistent(name = "ldapUser"),
        @Persistent(name = "managedUser"),
        @Persistent(name = "oidcUser"),
        @Persistent(name = "project"),
        @Persistent(name = "permission")
})
@FetchGroup(name = "LDAP", members = {
        @Persistent(name = "ldapUser"),
        @Persistent(name = "project"),
        @Persistent(name = "permission")
})
@FetchGroup(name = "MANAGED", members = {
        @Persistent(name = "managedUser"),
        @Persistent(name = "project"),
        @Persistent(name = "permission")
})
@FetchGroup(name = "OIDC", members = {
        @Persistent(name = "oidcUser"),
        @Persistent(name = "project"),
        @Persistent(name = "permission")
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EffectivePermission implements Serializable {

    private static final long serialVersionUID = -9033916273960513493L;

    /**
     * Defines JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL,
        LDAP,
        MANAGED,
        OIDC
    }

    @Persistent
    @Column(name = "LDAPUSER_ID")
    private LdapUser ldapUser;

    @Persistent
    @Column(name = "MANAGEDUSER_ID")
    private ManagedUser managedUser;

    @Persistent
    @Column(name = "OIDCUSER_ID")
    private OidcUser oidcUser;

    @Persistent
    @Column(name = "PROJECT_ID", allowsNull = "false")
    private Project project;

    @Persistent
    @Embedded(members = {
            @Persistent(name = "id", column = "PERMISSION_ID"),
            @Persistent(name = "name", column = "PERMISSION_NAME")
    })
    private Permission permission;

}
