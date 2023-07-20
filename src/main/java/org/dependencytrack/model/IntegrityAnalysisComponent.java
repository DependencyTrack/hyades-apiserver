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
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.UUID;

/**
 * Tracks integrity analysis results for components tracked by their uuid's.
 *
 * @author Meha Bhargava
 */
@PersistenceCapable(table = "INTEGRITY_ANALYSIS_COMPONENT")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntegrityAnalysisComponent {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;


    /**
     * This is an indirect representation of a the Package URL "type" field.
     */
    @Persistent(defaultFetchGroup = "true")
    @Column(name = "REPOSITORY_TYPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private RepositoryType repositoryType;

    /**
     * This is a representation of the Package URL "namespace" field.
     */
    @Persistent
    @Column(name = "COMPONENT_UUID")
    @NotNull
    private UUID uuid;

    /**
     * This is a representation of the Package URL "name" field.
     */
    @Persistent
    @Column(name = "REPOSITORY_URL", allowsNull = "false")
    @NotNull
    private String repositoryUrl;

    /**
     * The latest version of the component.
     */
    @Persistent
    @Column(name = "MD5HASH_MATCHED", allowsNull = "false")
    @NotNull
    private String md5HashMatched;

    @Persistent
    @Column(name = "SHA256_MATCHED", allowsNull = "false")
    @NotNull
    private String sha256HashMatched;

    @Persistent
    @Column(name = "SHA1_MATCHED", allowsNull = "false")
    @NotNull
    private String sha1HashMatched;

    //last checked
    //


    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public void setRepositoryUrl(String repositoryUrl) {
        this.repositoryUrl = repositoryUrl;
    }

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

    @Persistent
    @Column(name = "INTEGRITYCHECKPASSED", allowsNull = "false")
    @NotNull
    private boolean integrityCheckPassed;

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    /**
     * The date in which the last version check of the component was made.
     */
    @Persistent
    @Column(name = "LAST_CHECK", allowsNull = "false")
    @NotNull
    private Date lastCheck;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public RepositoryType getRepositoryType() {
        return repositoryType;
    }

    public void setRepositoryType(RepositoryType repositoryType) {
        this.repositoryType = repositoryType;
    }

    public Date getLastCheck() {
        return lastCheck;
    }

    public void setLastCheck(Date lastCheck) {
        this.lastCheck = lastCheck;
    }
}
