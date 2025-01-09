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
package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.core.config.JdbiConfig;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

/**
 * @since 5.5.0
 */
public class ApiRequestConfig implements JdbiConfig<ApiRequestConfig> {

    private Set<OrderingColumn> orderingAllowedColumns = Collections.emptySet();
    private String orderingAlwaysBy = "";

    // TODO: Make this configurable via annotation when needed (similar to @AllowOrdering).
    //   In some queries the PROJECT table may be aliased (e.g. as P).
    private String projectTableAlias = "PROJECT";

    @SuppressWarnings("unused")
    public ApiRequestConfig() {
        // Used by JDBI to instantiate the class via reflection.
    }

    private ApiRequestConfig(final ApiRequestConfig that) {
        this.orderingAllowedColumns = Set.copyOf(that.orderingAllowedColumns);
        this.orderingAlwaysBy = that.orderingAlwaysBy;
        this.projectTableAlias = that.projectTableAlias;
    }

    @Override
    public ApiRequestConfig createCopy() {
        return new ApiRequestConfig(this);
    }

    Optional<OrderingColumn> orderingAllowedColumn(final String name) {
        return orderingAllowedColumns.stream()
                .filter(column -> column.name().equals(name))
                .findAny();
    }

    Set<OrderingColumn> orderingAllowedColumns() {
        return orderingAllowedColumns;
    }

    public void setOrderingAllowedColumns(final Set<OrderingColumn> orderingAllowedColumns) {
        this.orderingAllowedColumns = orderingAllowedColumns;
    }

    String orderingAlwaysBy() {
        return orderingAlwaysBy;
    }

    public void setOrderingAlwaysBy(final String orderingAlwaysBy) {
        this.orderingAlwaysBy = orderingAlwaysBy;
    }

    String projectAclProjectTableName() {
        return projectTableAlias;
    }

    public record OrderingColumn(String name, String queryName) {

        public OrderingColumn(final String name) {
            this(name, null);
        }

    }

}
