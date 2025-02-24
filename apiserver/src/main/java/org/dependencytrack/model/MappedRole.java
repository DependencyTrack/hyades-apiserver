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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;

/**
 * Model for associating a role on a given project with users.
 *
 * @author Allen Shearin
 * @since 5.6.0
 */
@PersistenceCapable(table = "PROJECT_ACCESS_ROLES")
@Unique(name = "LDAPUSERS_PROJECTS_ROLES_COMPOSITE_IDX",
        table = "LDAPUSERS_PROJECTS_ROLES",
        members = { "ldapUsers", "project", "role" },
        deferred = "true")
@Unique(name = "MANAGEDUSERS_PROJECTS_ROLES_COMPOSITE_IDX",
        table = "MANAGEDUSERS_PROJECTS_ROLES",
        members = { "managedUsers", "project", "role" },
        deferred = "true")
@Unique(name = "OIDCUSERS_PROJECTS_ROLES_COMPOSITE_IDX",
        table = "OIDCUSERS_PROJECTS_ROLES",
        members = { "oidcUsers", "project", "role" },
        deferred = "true")
@FetchGroup(name = "ALL", members = {
        @Persistent(name = "role"),
        @Persistent(name = "project"),
        @Persistent(name = "ldapUsers"),
        @Persistent(name = "managedUsers"),
        @Persistent(name = "oidcUsers")
})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MappedRole implements Serializable {

    private static final long serialVersionUID = 1982348710987098723L;

    /**
     * Defines JDO fetch groups for this class.
     */
    public enum FetchGroup {
        ALL
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "ROLE_ID", allowsNull = "false")
    @JsonIgnore
    private Role role;

    @Persistent
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @JsonIgnore
    private Project project;

    @Persistent(table = "LDAPUSERS_PROJECTS_ROLES", defaultFetchGroup = "true")
    @Join(column = "PROJECT_ACCESS_ROLE_ID")
    @Element(column = "LDAPUSER_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
    private List<LdapUser> ldapUsers;

    @Persistent(table = "MANAGEDUSERS_PROJECTS_ROLES")
    @Join(column = "PROJECT_ACCESS_ROLE_ID")
    @Element(column = "MANAGEDUSER_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
    private List<ManagedUser> managedUsers;

    @Persistent(table = "OIDCUSERS_PROJECTS_ROLES")
    @Join(column = "PROJECT_ACCESS_ROLE_ID")
    @Element(column = "OIDCUSER_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
    private List<OidcUser> oidcUsers;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public List<LdapUser> getLdapUsers() {
        return ldapUsers;
    }

    public void setLdapUsers(List<LdapUser> ldapUsers) {
        this.ldapUsers = ldapUsers;
    }

    public void addLdapUsers(LdapUser... ldapUsers) {
        if (this.ldapUsers == null) {
            this.ldapUsers = new ArrayList<>(Arrays.asList(ldapUsers));

            return;
        }

        for (var user : ldapUsers)
            if (!this.ldapUsers.contains(user))
                this.ldapUsers.add(user);
    }

    public List<ManagedUser> getManagedUsers() {
        return managedUsers;
    }

    public void setManagedUsers(List<ManagedUser> managedUsers) {
        this.managedUsers = managedUsers;
    }

    public void addManagedUsers(ManagedUser... managedUsers) {
        if (this.managedUsers == null) {
            this.managedUsers = new ArrayList<>(Arrays.asList(managedUsers));

            return;
        }

        for (var user : managedUsers)
            if (!this.managedUsers.contains(user))
                this.managedUsers.add(user);
    }

    public List<OidcUser> getOidcUsers() {
        return oidcUsers;
    }

    public void setOidcUsers(List<OidcUser> oidcUsers) {
        this.oidcUsers = oidcUsers;
    }

    public void addOidcUsers(OidcUser... oidcUsers) {
        if (this.oidcUsers == null) {
            this.oidcUsers = new ArrayList<>(Arrays.asList(oidcUsers));

            return;
        }

        for (var user : oidcUsers)
            if (!this.oidcUsers.contains(user))
                this.oidcUsers.add(user);
    }

}