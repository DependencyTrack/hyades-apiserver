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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.util.Date;

/**
 * Tracks integrity analysis results for components tracked by their uuid's.
 *
 * @author Meha Bhargava
 */
@PersistenceCapable(table = "COMPONENT_INTEGRITY_ANALYSIS")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ComponentIntegrityAnalysis {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;

    /**
     * This is a representation of the Package URL "name" field.
     */
    @Persistent
    @Column(name = "REPOSITORY_IDENTIFIER", allowsNull = "false")
    @NotNull
    private String repositoryIdentifier;

    /**
     * The latest version of the component.
     */
    @Persistent
    @Column(name = "MD5_HASH_MATCHED", allowsNull = "false")
    @NotNull
    private String md5HashMatched;

    @Persistent
    @Column(name = "SHA256_HASH_MATCHED", allowsNull = "false")
    @NotNull
    private String sha256HashMatched;

    @Persistent
    @Column(name = "SHA1_HASH_MATCHED", allowsNull = "false")
    @NotNull
    private String sha1HashMatched;

    @Persistent
    @Column(name = "INTEGRITY_CHECK_PASSED", allowsNull = "false")
    @NotNull
    private boolean integrityCheckPassed;

    /**
     * The date in which the last version check of the component was made.
     */
    @Persistent
    @Column(name = "LAST_CHECK", allowsNull = "false")
    @NotNull
    private Date lastCheck;

    public String isMd5HashMatched() {
        return md5HashMatched;
    }

    public void setMd5HashMatched(String md5HashMatched) {
        this.md5HashMatched = md5HashMatched;
    }

    public String isSha256HashMatched() {
        return sha256HashMatched;
    }

    public void setSha256HashMatched(String sha256HashMatched) {
        this.sha256HashMatched = sha256HashMatched;
    }

    public String isSha1HashMatched() {
        return sha1HashMatched;
    }

    public void setSha1HashMatched(String sha1HashMatched) {
        this.sha1HashMatched = sha1HashMatched;
    }

    public boolean isIntegrityCheckPassed() {
        return integrityCheckPassed;
    }

    public void setIntegrityCheckPassed(boolean integrityCheckPassed) {
        this.integrityCheckPassed = integrityCheckPassed;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Date getLastCheck() {
        return lastCheck;
    }

    public void setLastCheck(Date lastCheck) {
        this.lastCheck = lastCheck;
    }

    public String getRepositoryIdentifier() {
        return repositoryIdentifier;
    }

    public void setRepositoryIdentifier(String repositoryIdentifier) {
        this.repositoryIdentifier = repositoryIdentifier;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }
}
