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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import alpine.model.User;

import java.io.Serializable;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
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
@Index(name = "USER_PROJECT_ROLES_IDX", unique = "true", members = { "user", "project", "role" })
public class UserProjectRole implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "USER_ID")
    private User user;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "PROJECT_ID")
    private Project project;

    @Persistent(defaultFetchGroup = "true")
    @Column(name = "ROLE_ID")
    private Role role;

    public UserProjectRole() {}

    public UserProjectRole(final User user, final Project project, final Role role) {
        this.user = user;
        this.project = project;
        this.role = role;
    }

    public long getId() {
        return id;
    }

    public void setId(final long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(final User user) {
        this.user = user;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(final Project project) {
        this.project = project;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(final Role role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return "%s{user='%s', project='%s', role='%s'}".formatted(
                getClass().getSimpleName(), user.getUsername(), project.getName(), role.getName());
    }

}
