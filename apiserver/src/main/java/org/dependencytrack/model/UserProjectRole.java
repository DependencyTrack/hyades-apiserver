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

import alpine.model.User;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

/**
 * Base class for user-project-role mapping.
 *
 * @author Jonathan Howard
 * @since 5.6.0
 */
@PersistenceCapable(table = "USER_PROJECT_ROLES")
@JsonInclude(JsonInclude.Include.NON_NULL)
@PrimaryKey(name = "USER_PROJECT_ROLES_PK", columns = {
        @Column(name = "USER_ID"),
        @Column(name = "PROJECT_ID"),
        @Column(name = "ROLE_ID")
})
public class UserProjectRole implements Serializable {

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "ROLE_ID", allowsNull = "false")
    private Role role;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @Element(column = "USER_ID")
    @Order(extensions = @Extension(vendorName = "datanucleus", key = "list-ordering", value = "username ASC"))
    private List<User> users;

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    public void addUsers(User... users) {
        this.users = Objects.requireNonNullElse(this.users, new ArrayList<User>());
        this.users = Stream.concat(this.users.stream(), Arrays.stream(users))
                .distinct()
                .sorted(Comparator.comparing(User::getUsername))
                .toList();
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

}
