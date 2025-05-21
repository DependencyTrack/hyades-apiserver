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

import org.dependencytrack.persistence.QueryManager;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;

import javax.jdo.PersistenceManager;
import javax.sql.DataSource;

import static org.dependencytrack.util.PersistenceUtil.getDataSource;

/**
 * @since 5.6.0
 */
public class DslContextFactory {

    private DslContextFactory() {
    }

    public static DSLContext create() {
        try (final var qm = new QueryManager()) {
            return createFrom(qm.getPersistenceManager());
        }
    }

    public static DSLContext createFrom(final QueryManager qm) {
        return createFrom(qm.getPersistenceManager());
    }

    public static DSLContext createFrom(final PersistenceManager pm) {
        final DataSource dataSource = getDataSource(pm.getPersistenceManagerFactory());
        return DSL.using(dataSource, SQLDialect.POSTGRES);
    }

}
