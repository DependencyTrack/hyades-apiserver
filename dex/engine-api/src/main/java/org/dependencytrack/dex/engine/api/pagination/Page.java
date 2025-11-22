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
package org.dependencytrack.dex.engine.api.pagination;

import org.jspecify.annotations.Nullable;

import java.util.List;

import static java.util.Objects.requireNonNull;

public record Page<T>(List<T> items, @Nullable String nextPageToken, @Nullable TotalCount totalCount) {

    public record TotalCount(long value, Type type) {

        public enum Type {
            EXACT,
            AT_LEAST
        }

        public TotalCount {
            if (value < 0) {
                throw new IllegalArgumentException("count must not be negative");
            }
            requireNonNull(type, "type must not be null");
        }

    }

    public Page {
        requireNonNull(items, "items must not be null");
    }

    public Page(List<T> items) {
        this(items, null, null);
    }

    public Page(List<T> items, @Nullable String nextPageToken) {
        this(items, nextPageToken, null);
    }

    public Page<T> withTotalCount(long value, TotalCount.Type type) {
        return new Page<>(this.items, this.nextPageToken, new TotalCount(value, type));
    }

}
