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
package org.dependencytrack.persistence;

import org.datanucleus.api.jdo.JDOQuery;
import org.datanucleus.store.rdbms.query.StoredProcedureQuery;

import javax.jdo.Query;
import java.util.function.Consumer;

/**
 * Utility class to work with database stored procedures.
 *
 * @since 5.0.0
 */
public final class StoredProcedures {

    public enum Procedure {
        UPDATE_COMPONENT_METRICS,
        UPDATE_PROJECT_METRICS,
        UPDATE_PORTFOLIO_METRICS;

        private String quotedName() {
            // We use quoted identifiers by convention.
            return "\"%s\"".formatted(name());
        }
    }

    private StoredProcedures() {
    }

    /**
     * Execute a given stored procedure.
     *
     * @param procedure The {@link Procedure} to execute
     * @since 5.0.0
     */
    public static void execute(final Procedure procedure) {
        execute(procedure, query -> {
        });
    }

    /**
     * Execute a given stored procedure and customize the execution.
     *
     * @param procedure     The {@link Procedure} to execute
     * @param queryConsumer {@link Consumer} for customizing the {@link StoredProcedureQuery}
     * @since 5.0.0
     */
    public static void execute(final Procedure procedure, final Consumer<StoredProcedureQuery> queryConsumer) {
        try (final var qm = new QueryManager()) {
            final Query<?> query = qm.getPersistenceManager().newQuery("STOREDPROC", procedure.quotedName());
            try {
                final var spQuery = (StoredProcedureQuery) ((JDOQuery<?>) query).getInternalQuery();
                queryConsumer.accept(spQuery);
                spQuery.execute();
            } finally {
                query.closeAll();
            }
        }
    }

}
