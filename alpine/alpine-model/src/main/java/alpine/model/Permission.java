/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Persistable object representing a Permission.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class Permission implements Serializable {

    private static final long serialVersionUID = 1420020753285692448L;

    public Permission() {
    }

    public Permission(AccessResource resource, AccessLevel accessLevel, String description) {
        this.resource = resource;
        this.accessLevel = accessLevel;
        this.description = description;
    }

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "RESOURCE", allowsNull = "false", jdbcType = "VARCHAR")
    private AccessResource resource;

    @Persistent
    @Column(name = "ACCESS_LEVEL", allowsNull = "false", jdbcType = "VARCHAR")
    private AccessLevel accessLevel;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "CLOB")
    private String description;

    @Persistent(mappedBy = "permissions")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "name ASC"))
    @JsonIgnore
    private List<Team> teams;

    @Persistent(mappedBy = "permissions")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
    @JsonIgnore
    private List<User> users;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public AccessResource getResource() {
        return resource;
    }

    public void setResource(AccessResource resource) {
        this.resource = resource;
    }

    public AccessLevel getAccessLevel() {
        return accessLevel;
    }

    public void setAccessLevel(AccessLevel accessLevel) {
        this.accessLevel = accessLevel;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<Team> getTeams() {
        return teams;
    }

    public void setTeams(List<Team> teams) {
        this.teams = teams;
    }

    public List<OidcUser> getOidcUsers() {
        if (users == null) {
            return null;
        }

        return users.stream()
                .filter(user -> user instanceof OidcUser)
                .map(user -> (OidcUser) user)
                .toList();
    }

    public void setOidcUsers(List<OidcUser> oidcUsers) {
        this.users = Objects.requireNonNullElseGet(this.users, ArrayList::new);
        this.users.addAll(oidcUsers);
    }

    public List<LdapUser> getLdapUsers() {
        if (users == null) {
            return null;
        }

        return users.stream()
                .filter(user -> user instanceof LdapUser)
                .map(user -> (LdapUser) user)
                .toList();
    }

    public void setLdapUsers(List<LdapUser> ldapUsers) {
        this.users = Objects.requireNonNullElseGet(this.users, ArrayList::new);
        this.users.addAll(ldapUsers);
    }

    public List<ManagedUser> getManagedUsers() {
        if (users == null) {
            return null;
        }

        return users.stream()
                .filter(user -> user instanceof ManagedUser)
                .map(user -> (ManagedUser) user)
                .toList();
    }

    public void setManagedUsers(List<ManagedUser> managedUsers) {
        this.users = Objects.requireNonNullElseGet(this.users, ArrayList::new);
        this.users.addAll(managedUsers);
    }

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    @Override
    public String toString() {
        return "%s{resource=%s, accessLevel=%s, description='%s'}".formatted(
                getClass().getSimpleName(),
                resource.name(),
                accessLevel.name(),
                description);
    }

}
