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
package org.dependencytrack.persistence.jooq;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.persistence.QueryManager;
import org.jooq.DSLContext;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DslContextFactoryTest extends PersistenceCapableTest {

    @Test
    public void createShouldReturnDslContext() {
        final DSLContext context = DslContextFactory.create();
        assertThat(context.selectOne().fetchOneInto(Integer.class)).isOne();
    }

    @Test
    public void createFromShouldReturnDslContextFromQueryManager() {
        try (final var qm = new QueryManager()) {
            final DSLContext context = DslContextFactory.createFrom(qm);
            assertThat(context.selectOne().fetchOneInto(Integer.class)).isOne();
        }
    }

    @Test
    public void createFromShouldReturnDslContextFromPersistenceManager() {
        try (final var qm = new QueryManager()) {
            final DSLContext context = DslContextFactory.createFrom(qm.getPersistenceManager());
            assertThat(context.selectOne().fetchOneInto(Integer.class)).isOne();
        }
    }

}