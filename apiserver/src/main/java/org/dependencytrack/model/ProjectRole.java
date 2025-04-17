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

import com.fasterxml.jackson.annotation.JsonInclude;

import alpine.model.LdapUser;
import alpine.model.ManagedUser;
import alpine.model.OidcUser;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.FetchGroup;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceAware;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.Unique;

/**
 * Base class for user-project-role mapping.
 *
 * @author Jonathan Howard
 * @since 5.6.0
 */
@PersistenceAware
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class ProjectRole implements Serializable {

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "ROLE_ID", allowsNull = "false")
    private Role role;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    private Project project;

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

    /**
     * Model for associating a role on a given project with LDAP users.
     *
     * @author Allen Shearin
     * @since 5.6.0
     */
    @PersistenceCapable(table = "LDAPUSERS_PROJECTS_ROLES")
    @Unique(name = "LDAPUSERS_PROJECTS_ROLES_COMPOSITE_IDX", members = { "ldapUsers", "project", "role" })
    @FetchGroup(name = "ALL", members = {
            @Persistent(name = "role"),
            @Persistent(name = "project"),
            @Persistent(name = "ldapUsers")
    })
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class LdapUserProjectRole extends ProjectRole {

        private static final long serialVersionUID = 6018553054343647649L;

        /**
         * Defines JDO fetch groups for this class.
         */
        public enum FetchGroup {
            ALL
        }

        @Persistent(defaultFetchGroup = "true")
        @Column(name = "LDAPUSER_ID", allowsNull = "false")
        @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
        private List<LdapUser> ldapUsers;

        public List<LdapUser> getLdapUsers() {
            return ldapUsers;
        }

        public void setLdapUsers(List<LdapUser> ldapUsers) {
            this.ldapUsers = ldapUsers;
        }

        public void addLdapUsers(LdapUser... ldapUsers) {
            this.ldapUsers = Objects.requireNonNullElse(this.ldapUsers, new ArrayList<LdapUser>());
            this.ldapUsers = Stream.concat(this.ldapUsers.stream(), Arrays.stream(ldapUsers))
                    .distinct()
                    .sorted(Comparator.comparing(LdapUser::getUsername))
                    .toList();
        }

    }

    /**
     * Model for associating a role on a given project with managed users.
     *
     * @author Allen Shearin
     * @since 5.6.0
     */
    @PersistenceCapable(table = "MANAGEDUSERS_PROJECTS_ROLES")
    @Unique(name = "MANAGEDUSERS_PROJECTS_ROLES_COMPOSITE_IDX", members = { "managedUsers", "project", "role" })
    @FetchGroup(name = "ALL", members = {
            @Persistent(name = "role"),
            @Persistent(name = "project"),
            @Persistent(name = "managedUsers")
    })
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ManagedUserProjectRole extends ProjectRole {

        private static final long serialVersionUID = -380122087527236991L;

        /**
         * Defines JDO fetch groups for this class.
         */
        public enum FetchGroup {
            ALL
        }

        @Persistent(defaultFetchGroup = "true")
        @Column(name = "MANAGEDUSER_ID", allowsNull = "false")
        @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
        private List<ManagedUser> managedUsers;

        public List<ManagedUser> getManagedUsers() {
            return managedUsers;
        }

        public void setManagedUsers(List<ManagedUser> managedUsers) {
            this.managedUsers = managedUsers;
        }

        public void addManagedUsers(ManagedUser... managedUsers) {
            this.managedUsers = Objects.requireNonNullElse(this.managedUsers, new ArrayList<ManagedUser>());
            this.managedUsers = Stream.concat(this.managedUsers.stream(), Arrays.stream(managedUsers))
                    .distinct()
                    .sorted(Comparator.comparing(ManagedUser::getUsername))
                    .toList();
        }

    }

    /**
     * Model for associating a role on a given project with OIDC users.
     *
     * @author Allen Shearin
     * @since 5.6.0
     */
    @PersistenceCapable(table = "OIDCUSERS_PROJECTS_ROLES")
    @Unique(name = "OIDCUSERS_PROJECTS_ROLES_COMPOSITE_IDX", members = { "oidcUsers", "project", "role" })
    @FetchGroup(name = "ALL", members = {
            @Persistent(name = "role"),
            @Persistent(name = "project"),
            @Persistent(name = "oidcUsers")
    })
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class OidcUserProjectRole extends ProjectRole {

        private static final long serialVersionUID = -5029209056240375886L;

        /**
         * Defines JDO fetch groups for this class.
         */
        public enum FetchGroup {
            ALL
        }

        @Persistent(defaultFetchGroup = "true")
        @Column(name = "OIDCUSER_ID", allowsNull = "false")
        @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
        private List<OidcUser> oidcUsers;

        public List<OidcUser> getOidcUsers() {
            return oidcUsers;
        }

        public void setOidcUsers(List<OidcUser> oidcUsers) {
            this.oidcUsers = oidcUsers;
        }

        public void addOidcUsers(OidcUser... oidcUsers) {
            this.oidcUsers = Objects.requireNonNullElse(this.oidcUsers, new ArrayList<OidcUser>());
            this.oidcUsers = Stream.concat(this.oidcUsers.stream(), Arrays.stream(oidcUsers))
                    .distinct()
                    .sorted(Comparator.comparing(OidcUser::getUsername))
                    .toList();
        }

    }

}
