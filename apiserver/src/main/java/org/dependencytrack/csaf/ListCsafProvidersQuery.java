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
package org.dependencytrack.csaf;

import org.jspecify.annotations.Nullable;

/**
 * @since 5.7.0
 */
public record ListCsafProvidersQuery(
        @Nullable Boolean enabled,
        @Nullable Boolean discovered,
        @Nullable String searchText,
        @Nullable String pageToken,
        int limit) {

    public ListCsafProvidersQuery() {
        this(null, null, null, null, 100);
    }

    public ListCsafProvidersQuery withEnabled(@Nullable Boolean enabled) {
        return new ListCsafProvidersQuery(enabled, this.discovered, this.searchText, this.pageToken, this.limit);
    }

    public ListCsafProvidersQuery withDiscovered(@Nullable Boolean discovered) {
        return new ListCsafProvidersQuery(this.enabled, discovered, this.searchText, this.pageToken, this.limit);
    }

    public ListCsafProvidersQuery withSearchText(@Nullable String searchText) {
        return new ListCsafProvidersQuery(this.enabled, this.discovered, searchText, this.pageToken, this.limit);
    }

    public ListCsafProvidersQuery withPageToken(@Nullable String pageToken) {
        return new ListCsafProvidersQuery(this.enabled, this.discovered, this.searchText, pageToken, this.limit);
    }

    public ListCsafProvidersQuery withLimit(int limit) {
        return new ListCsafProvidersQuery(this.enabled, this.discovered, this.searchText, this.pageToken, limit);
    }

}
