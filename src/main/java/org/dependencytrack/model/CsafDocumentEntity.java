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
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.time.Instant;

/**
 * Model for configured CSAF document entities.
 *
 *
 * @since 5.6.0 //TODO set when merged
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CsafDocumentEntity implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private long id;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(regexp = RegexSequence.Definition.PRINTABLE_CHARS, message = "The name may only contain printable characters")
    @Persistent(name = "NAME")
    private String name;

    @Persistent
    @Column(name = "URL")
    @NotBlank
    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    private String url;

    @Persistent(defaultFetchGroup = "false")
    @Column(name = "CONTENT", jdbcType = "CLOB")
    private String content;

    @Persistent
    @Column(name = "PUBLISHERNAMESPACE")
    private String publisherNamespace;

    @Persistent
    @Column(name = "TRACKINGID")
    private String trackingID;

    @Persistent
    @Column(name = "TRACKINGVERSION")
    private String trackingVersion;

    @Persistent
    @Column(name = "SEEN")
    private boolean seen;

    @Persistent
    @Column(name = "LASTFETCHED")
    private Instant lastFetched;

    public CsafDocumentEntity() {
        // no args for jdo
    }

    public CsafDocumentEntity(String name, String url) {
        this.name = name;
        this.url = url;
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

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getPublisherNamespace() {
        return publisherNamespace;
    }

    public void setPublisherNamespace(String publisherNamespace) {
        this.publisherNamespace = publisherNamespace;
    }

    public String getTrackingID() {
        return trackingID;
    }

    public void setTrackingID(String trackingID) {
        this.trackingID = trackingID;
    }

    public String getTrackingVersion() {
        return trackingVersion;
    }

    public void setTrackingVersion(String trackingVersion) {
        this.trackingVersion = trackingVersion;
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

    public void setLastFetched(java.sql.Timestamp lastFetched) {
        setLastFetched(lastFetched.toInstant());
    }

    @Override
    public String toString() {
        return "CsafDocumentEntity{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", url='" + url + '\'' +
                ", publisherNamespace='" + publisherNamespace + '\'' +
                ", trackingID='" + trackingID + '\'' +
                ", trackingVersion='" + trackingVersion + '\'' +
                ", seen=" + seen +
                ", lastFetched=" + lastFetched +
                '}';
    }
}
