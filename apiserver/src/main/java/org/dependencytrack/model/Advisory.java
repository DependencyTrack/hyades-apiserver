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

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.time.Instant;

/**
 * Model for a security advisory which is fetched from an external source. It usually contains
 * one or more vulnerabilities.
 *
 * @since 5.7.0
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Advisory implements Serializable {

    /**
     * The internal database id of the advisory.
     */
    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private long id;

    /**
     * A machine-readable name of the advisory. In CSAF documents this is the "document.tracking.id" field.
     */
    @Persistent
    @Column(name = "NAME")
    private String name;

    /**
     * The version of the advisory. In CSAF documents this is the "document.tracking.version" field.
     */
    @Persistent
    @Column(name = "VERSION")
    private String version;

    /**
     * The publisher (namespace) of the advisory. In CSAF documents this is the "document.publisher.namespace" field.
     */
    @Persistent
    @Column(name = "PUBLISHER")
    private String publisher;

    /**
     * A human-readable title for the advisory.
     */
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The title may only contain printable characters")
    @Persistent(name = "TITLE")
    private String title;

    /**
     * The URL where the advisory can be found externally.
     */
    @Persistent
    @Column(name = "URL")
    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String url;

    /**
     * The format of the advisory, e.g., "CSAF".
     */
    @Persistent
    @Column(name = "FORMAT")
    private String format;

    /**
     * The raw content of the advisory, typically in JSON format.
     */
    @Persistent
    @Column(name = "CONTENT", jdbcType = "CLOB")
    private String content;

    /**
     * Whether the advisory has been marked as "seen" in the UI. This is a hint for users
     * to identify new advisories since their last visit.
     */
    @Persistent
    @Column(name = "SEEN")
    private boolean seen;

    /**
     * The time when the advisory was last fetched from the external source.
     */
    @Persistent
    @Column(name = "LASTFETCHED")
    private Instant lastFetched;

    @Persistent(table = "ADVISORIES_VULNERABILITIES")
    @Join(column = "ADVISORY_ID", foreignKey = "ADVISORIES_VULNERABILITIES_ADVISORY_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Element(column = "VULNERABILITY_ID", foreignKey = "ADVISORIES_VULNERABILITIES_VULNERABILITY_FK", deleteAction = ForeignKeyAction.CASCADE)
    @Order(extensions = @javax.jdo.annotations.Extension(vendorName = "datanucleus", key = "list-ordering", value = "id ASC"))
    private java.util.List<Vulnerability> vulnerabilities;

    public Advisory() {
        // no args for jdo
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisherNamespace) {
        this.publisher = publisherNamespace;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public boolean isSeen() {
        return seen;
    }

    public void setSeen(boolean seen) {
        this.seen = seen;
    }

    public Instant getLastFetched() {
        return lastFetched;
    }

    public void setLastFetched(Instant lastFetched) {
        this.lastFetched = lastFetched;
    }

    public java.util.List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(java.util.List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        if (this.vulnerabilities == null) {
            this.vulnerabilities = new java.util.ArrayList<>();
        }
        this.vulnerabilities.add(vulnerability);
    }

    public void removeVulnerability(Vulnerability vulnerability) {
        if (this.vulnerabilities != null) {
            this.vulnerabilities.remove(vulnerability);
        }
    }

    @Override
    public String toString() {
        return "Advisory{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", url='" + url + '\'' +
                ", publisher='" + publisher + '\'' +
                ", name='" + name + '\'' +
                ", version='" + version + '\'' +
                ", seen=" + seen +
                ", lastFetched=" + lastFetched +
                '}';
    }

}
