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

import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.util.Date;

@PersistenceCapable(table = "INTEGRITY_META_COMPONENT")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntegrityMetaComponent implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "MD5", jdbcType = "VARCHAR", length = 32)
    @Pattern(regexp = "^[0-9a-fA-F]{32}$", message = "The MD5 hash must be a valid 32 character HEX number")
    private String md5;

    @Persistent
    @Column(name = "SHA1", jdbcType = "VARCHAR", length = 40)
    @Pattern(regexp = "^[0-9a-fA-F]{40}$", message = "The SHA1 hash must be a valid 40 character HEX number")
    private String sha1;

    @Persistent
    @Column(name = "SHA256", jdbcType = "VARCHAR", length = 64)
    @Pattern(regexp = "^[0-9a-fA-F]{64}$", message = "The SHA-256 hash must be a valid 64 character HEX number")
    private String sha256;

    public String getSha512() {
        return sha512;
    }

    public void setSha512(String sha512) {
        this.sha512 = sha512;
    }

    @Persistent
    @Column(name = "SHA512", jdbcType = "VARCHAR", length = 128)
    @Pattern(regexp = "^[0-9a-fA-F]{128}$", message = "The SHA-512 hash must be a valid 128 character HEX number")
    private String sha512;

    @Persistent
    @Column(name = "PURL", allowsNull = "false", jdbcType = "VARCHAR", length = 1024)
    @Index(name = "PURL_IDX")
    @Size(max = 1024)
    @com.github.packageurl.validator.PackageURL
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Unique
    @NotNull
    private String purl;

    /*
     * Published date of current version of component
     */
    @Persistent
    @Column(name = "PUBLISHED_AT")
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date publishedAt;

    @Persistent
    @Column(name = "LAST_FETCH")
    @Index(name = "LAST_FETCH_IDX")
    @Schema(type = "integer", format = "int64", requiredMode = Schema.RequiredMode.REQUIRED, description = "UNIX epoch timestamp in milliseconds")
    private Date lastFetch;

    @Persistent
    @Column(name = "STATUS", jdbcType = "VARCHAR", length = 64)
    @Extension(vendorName = "datanucleus", key = "enum-check-constraint", value = "true")
    private FetchStatus status;

    @Persistent
    @Column(name = "REPOSITORY_URL", jdbcType = "VARCHAR", length = 1024)
    private String repositoryUrl;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public Date getPublishedAt() {
        return publishedAt;
    }

    public void setPublishedAt(Date publishedAt) {
        this.publishedAt = publishedAt;
    }

    public Date getLastFetch() {
        return lastFetch;
    }

    public String getRepositoryUrl() {
        return repositoryUrl;
    }

    public void setRepositoryUrl(String repositoryUrl) {
        this.repositoryUrl = repositoryUrl;
    }

    public void setLastFetch(Date lastFetch) {
        this.lastFetch = lastFetch;
    }

    public FetchStatus getStatus() {
        return status;
    }

    public void setStatus(FetchStatus status) {
        this.status = status;
    }
}
