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
package org.dependencytrack.persistence.datanucleus.method;

import org.datanucleus.store.query.expression.Expression;
import org.datanucleus.store.rdbms.mapping.java.JavaTypeMapping;
import org.datanucleus.store.rdbms.sql.SQLStatement;
import org.datanucleus.store.rdbms.sql.expression.ArrayLiteral;
import org.datanucleus.store.rdbms.sql.expression.BooleanExpression;
import org.datanucleus.store.rdbms.sql.expression.BooleanLiteral;
import org.datanucleus.store.rdbms.sql.expression.ObjectExpression;
import org.datanucleus.store.rdbms.sql.expression.SQLExpression;
import org.datanucleus.store.rdbms.sql.expression.StringExpression;
import org.datanucleus.store.rdbms.sql.expression.StringLiteral;
import org.datanucleus.store.rdbms.sql.method.SQLMethod;
import org.dependencytrack.model.Project;

import java.util.List;
import java.util.StringJoiner;

/**
 * @since 5.6.0
 */
public class ProjectIsAccessibleByMethod implements SQLMethod {

    @Override
    public SQLExpression getExpression(
            final SQLStatement stmt,
            final SQLExpression expr,
            final List<SQLExpression> args) {
        if (!(expr instanceof final ObjectExpression objectExpr)) {
            // DataNucleus should prevent this from ever happening since
            // the method is explicitly registered for java.lang.Object.
            throw new IllegalStateException(
                    "Expected expression to be of type %s, but got: %s".formatted(
                            ObjectExpression.class.getName(), expr.getClass().getName()));
        }

        final String objectTypeName = objectExpr.getJavaTypeMapping().getType();
        if (!Project.class.getName().equals(objectTypeName)) {
            throw new IllegalStateException(
                    "isAccessibleBy is only allowed for objects of type %s, but was called on %s".formatted(
                            Project.class.getName(), objectTypeName));
        }

        if (args == null) {
            throw new IllegalArgumentException();
        } else if (args.size() != 1) {
            throw new IllegalArgumentException("Expected exactly one argument, but got " + args.size());
        }

        // TODO: When a list, set, etc. is passed as argument, it will be of type CollectionLiteral.
        //  Array literals are easier to verify the type of, hence we're focusing on that for now.

        if (!(args.getFirst() instanceof final ArrayLiteral arrayLiteralArg)) {
            throw new IllegalArgumentException(
                    "Expected argument to be of type %s, but got %s".formatted(
                            ArrayLiteral.class.getName(), args.getFirst().getClass().getName()));
        }
        if (!(arrayLiteralArg.getValue() instanceof final Long[] teamIds)) {
            throw new IllegalArgumentException(
                    "Expected array argument to be of type %s, but got %s".formatted(
                            Long[].class.getName(), arrayLiteralArg.getValue().getClass().getName()));
        }

        final JavaTypeMapping booleanTypeMapping = stmt.getSQLExpressionFactory().getMappingForType(Boolean.class);
        final JavaTypeMapping stringTypeMapping = stmt.getSQLExpressionFactory().getMappingForType(String.class);

        // Transform the array literal to have the correct type for Postgres.
        // Will result in the following expression: cast('{1,2,3}' as bigint[])
        final StringJoiner joiner = new StringJoiner(",", "{", "}");
        for (final Long teamId : teamIds) {
            joiner.add(String.valueOf(teamId));
        }
        final var teamIdsLiteral = new StringLiteral(
                stmt, stringTypeMapping, joiner.toString(), null);
        final var teamIdsExpr = new StringExpression(
                stmt, stringTypeMapping, "cast", List.of(teamIdsLiteral), List.of("bigint[]"));

        // NB: objectExpr will compile to a reference of the object table's ID column, e.g.:
        //   * "A0"."ID"
        //   * "B0"."PROJECT_ID"
        final var hasProjectAccessFunctionExpr = new StringExpression(
                stmt, stringTypeMapping, "has_project_access", List.of(objectExpr, teamIdsExpr));

        // Wrap the function call in a boolean expression. Final result(s) will be:
        //   * has_project_access("A0"."ID", cast('{1,2,3}' as bigint[])) = TRUE
        //   * has_project_access("B0"."PROJECT_ID", cast('{1,2,3}' as bigint[])) = TRUE
        final var booleanTrueLiteral = new BooleanLiteral(stmt, booleanTypeMapping, Boolean.TRUE, null);
        return new BooleanExpression(hasProjectAccessFunctionExpr, Expression.OP_EQ, booleanTrueLiteral);
    }

}
