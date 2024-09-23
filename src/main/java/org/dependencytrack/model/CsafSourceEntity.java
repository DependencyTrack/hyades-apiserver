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
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import java.io.Serializable;
import java.time.Instant;

/**
 * Model for configured CSAF source entities.
 *
 * 
 * @since 5.6.0 //TODO set when merged
 */
@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CsafSourceEntity implements Serializable {

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

    @Persistent
    @Column(name = "ENABLED")
    @NotNull
    private boolean enabled;

    @Persistent(defaultFetchGroup = "false")
    @Column(name = "CONTENT", jdbcType = "CLOB")
    private String content;

    @Persistent
    @Column(name = "SEEN")
    private boolean seen;

    @Persistent
    @Column(name = "LASTFETCHED")
    private Instant lastFetched;

    @Persistent
    @Column(name = "AGGREGATOR")
    private boolean aggregator;

    @Persistent
    @Column(name = "DISCOVERY")
    private boolean discovery;

    public CsafSourceEntity() {
        // no args for jdo
    }

    public CsafSourceEntity(String name, String url) {
        this.name = name;
        this.url = url;
    }

    public long getId() {
        return id;
    }

    public void setEntryId(long id) {
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

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
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

    public boolean isAggregator() {
        return aggregator;
    }

    public void setAggregator(boolean aggregator) {
        this.aggregator = aggregator;
    }

    public boolean isDiscovery() {
        return discovery;
    }

    public void setDiscovery(boolean discovery) {
        this.discovery = discovery;
    }

    @Override
    public String toString() {
        return "CsafSourceEntity{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", url='" + url + '\'' +
                ", enabled=" + enabled +
                ", content='" + content + '\'' +
                ", seen=" + seen +
                ", lastFetched=" + lastFetched +
                ", aggregator=" + aggregator +
                ", discovery=" + discovery +
                '}';
    }
}
