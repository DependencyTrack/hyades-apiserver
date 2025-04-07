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
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.mapper.MappingException;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class PaginatedResultRowReducerTest extends PersistenceCapableTest {

    public static final class StringPaginatedResultRowReducer extends PaginatedResultRowReducer<String> {

        public StringPaginatedResultRowReducer() {
            super(String.class);
        }

    }

    public interface TestDao {

        @SqlQuery("""
                SELECT "NAME", COUNT(*) OVER () AS "totalCount" FROM "PROJECT"
                <#if limit??>
                LIMIT ${limit}
                </#if>
                """)
        @UseRowReducer(StringPaginatedResultRowReducer.class)
        PaginatedResult getProjectNamesPage(@Define Integer limit);

        @SqlQuery("SELECT \"NAME\" FROM \"PROJECT\"")
        @UseRowReducer(StringPaginatedResultRowReducer.class)
        PaginatedResult getProjectNamesPageWithoutTotalCount();

    }

    @Before
    public void setUp() {
        for (int i = 0; i < 10; i++) {
            final var project = new Project();
            project.setName("project-" + i);
            qm.persist(project);
        }
    }

    @Test
    public void testWithoutLimit() {
        final PaginatedResult result = withJdbiHandle(handle -> handle
                .registerRowMapper(String.class, (rs, ctx) -> rs.getString("NAME"))
                .attach(TestDao.class)
                .getProjectNamesPage(null));

        assertThat(result.getTotal()).isEqualTo(10);
        assertThat(result.getObjects()).hasSize(10);
    }

    @Test
    public void testWithLimit() {
        final PaginatedResult result = withJdbiHandle(handle -> handle
                .registerRowMapper(String.class, (rs, ctx) -> rs.getString("NAME"))
                .attach(TestDao.class)
                .getProjectNamesPage(5));

        assertThat(result.getTotal()).isEqualTo(10);
        assertThat(result.getObjects()).hasSize(5);
    }

    @Test
    public void testWithoutTotalCountColumn() {
        assertThatExceptionOfType(MappingException.class)
                .isThrownBy(() -> useJdbiHandle(handle -> handle.attach(TestDao.class).getProjectNamesPageWithoutTotalCount()));
    }

}