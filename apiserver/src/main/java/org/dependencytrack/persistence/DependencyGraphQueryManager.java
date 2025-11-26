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

import alpine.persistence.ScopedCustomization;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.DependencyGraphEdge;
import org.dependencytrack.model.DependencyGraphEdgeClosure;
import org.postgresql.copy.CopyManager;
import org.postgresql.core.BaseConnection;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.jdo.datastore.JDOConnection;
import java.io.IOException;
import java.io.StringReader;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;

import static org.datanucleus.PropertyNames.PROPERTY_QUERY_SQL_ALLOWALL;

/**
 * @since 5.7.0
 */
public final class DependencyGraphQueryManager extends QueryManager {

    DependencyGraphQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    DependencyGraphQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    @Override
    public void updateDependencyGraph(
            final long projectId,
            final Map<DependencyGraphEdge, DependencyGraphEdgeClosure> closureByEdge) {
        final var csv = new StringBuilder();
        for (final var entry : closureByEdge.entrySet()) {
            final DependencyGraphEdge edge = entry.getKey();
            final DependencyGraphEdgeClosure closure = entry.getValue();

            csv
                    .append(projectId).append(',')
                    .append(edge.ancestor().type()).append(',')
                    .append(edge.ancestor().id()).append(',')
                    .append(edge.descendant().type()).append(',')
                    .append(edge.descendant().id()).append(',')
                    .append(closure.minDepth()).append(',')
                    .append(closure.maxDepth()).append('\n');
        }

        deleteDependencyGraph(projectId);

        final JDOConnection jdoConnection = pm.getDataStoreConnection();
        final var nativeConnection = (Connection) jdoConnection.getNativeConnection();
        try (final var csvReader = new StringReader(csv.toString())) {
            final var pgConnection = nativeConnection.unwrap(BaseConnection.class);
            new CopyManager(pgConnection).copyIn(/* language=SQL */ """
                    COPY "DEPENDENCY_GRAPH" (
                      "PROJECT_ID"
                    , "ANCESTOR_TYPE"
                    , "ANCESTOR_ID"
                    , "DESCENDANT_TYPE"
                    , "DESCENDANT_ID"
                    , "MIN_DEPTH"
                    , "MAX_DEPTH"
                    )
                    FROM STDIN WITH (FORMAT CSV)
                    """,
                    csvReader);
        } catch (IOException | SQLException e) {
            throw new IllegalArgumentException(e);
        } finally {
            jdoConnection.close();
        }
    }

    public long getDependencyGraphLeafNodes(final long projectId) {
        final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                SELECT COUNT(*)
                  FROM "DEPENDENCY_GRAPH"
                 WHERE "PROJECT_ID" = ?
                   AND "MAX_DEPTH" = 0
                """);

        query.setParameters(projectId);
        return executeAndCloseResultUnique(query, Long.class);
    }

    private boolean deleteDependencyGraph(final long projectId) {
        try (final var ignored = new ScopedCustomization(pm)
                .withProperty(PROPERTY_QUERY_SQL_ALLOWALL, "true")) {
            final Query<?> query = pm.newQuery(Query.SQL, /* language=SQL */ """
                    DELETE FROM "DEPENDENCY_GRAPH"
                     WHERE "PROJECT_ID" = ?
                    """);
            final long rowsDeleted = (Long) query.execute(projectId);
            return rowsDeleted > 0;
        }
    }

}
