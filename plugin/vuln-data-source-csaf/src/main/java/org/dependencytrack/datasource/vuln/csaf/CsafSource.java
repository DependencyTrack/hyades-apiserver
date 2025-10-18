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
package org.dependencytrack.datasource.vuln.csaf;

import org.jetbrains.annotations.Nullable;

import java.time.Instant;

/**
 * A CSAF source, either an aggregator or a provider.
 *
 * @since 5.7.0
 */
public class CsafSource {

    /**
     * The unique identifier of the source.
     */
    private int id;

    /**
     * The name of the source.
     */
    private String name;

    /**
     * The URL or domain of the source.
     */
    private String url;

    /**
     * Whether the source is an aggregator (true) or a provider (false).
     */
    private boolean aggregator;

    /**
     * Whether the source was discovered (true) or manually added (false).
     */
    private boolean discovered;

    /**
     * Whether the source is enabled (true) or disabled (false).
     */
    private boolean enabled;

    /**
     * Whether the URL is a domain (true) or a full URL (false).
     */
    private boolean domain;

    /**
     * The timestamp of the last successful fetch from this source (or null).
     */
    @Nullable
    private Instant lastFetched;

    public CsafSource() {}

    public CsafSource(String name,
                      String url,
                      boolean isAggregator,
                      boolean isDiscovered,
                      boolean isEnabled,
                      boolean isDomain) {
        this.name = name;
        this.url = url;
        this.aggregator = isAggregator;
        this.discovered = isDiscovered;
        this.enabled = isEnabled;
        this.domain = isDomain;
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public boolean getEnabled() {
        return enabled;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isAggregator() {
        return aggregator;
    }

    public void setAggregator(boolean aggregator) {
        this.aggregator = aggregator;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Nullable
    public Instant getLastFetched() {
        return lastFetched;
    }

    public void setLastFetched(@Nullable Instant lastFetched) {
        this.lastFetched = lastFetched;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public boolean isDiscovered() {
        return discovered;
    }

    public void setDiscovered(boolean discovered) {
        this.discovered = discovered;
    }

    public boolean isDomain() {
        return domain;
    }

    public void setDomain(boolean domain) {
        this.domain = domain;
    }

}
