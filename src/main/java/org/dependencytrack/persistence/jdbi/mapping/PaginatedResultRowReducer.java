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
package org.dependencytrack.persistence.jdbi.mapping;

import alpine.persistence.PaginatedResult;
import org.jdbi.v3.core.result.RowReducer;
import org.jdbi.v3.core.result.RowView;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class PaginatedResultRowReducer<T> implements RowReducer<PaginatedResultRowReducer.ResultContainer<T>, PaginatedResult> {

    public static final class ResultContainer<T> {

        private long totalCount;
        private final List<T> results = new ArrayList<>();

        private void addResult(final T result) {
            results.add(result);
        }

    }

    private final Class<T> elementClass;

    public PaginatedResultRowReducer(final Class<T> elementClass) {
        this.elementClass = elementClass;
    }

    @Override
    public ResultContainer<T> container() {
        return new ResultContainer<>();
    }

    @Override
    public void accumulate(final ResultContainer<T> container, final RowView rowView) {
        container.totalCount = rowView.getColumn("totalCount", Long.class);
        container.addResult(rowView.getRow(elementClass));
    }

    @Override
    public Stream<PaginatedResult> stream(final ResultContainer<T> container) {
        return Stream.of(new PaginatedResult().objects(container.results).total(container.totalCount));
    }

}
