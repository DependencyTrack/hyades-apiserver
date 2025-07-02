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
import org.datanucleus.store.rdbms.sql.expression.IntegerLiteral;
import org.datanucleus.store.rdbms.sql.expression.ObjectExpression;
import org.datanucleus.store.rdbms.sql.expression.SQLExpression;
import org.datanucleus.store.rdbms.sql.expression.SQLLiteral;
import org.datanucleus.store.rdbms.sql.expression.StringExpression;
import org.datanucleus.store.rdbms.sql.expression.StringLiteral;
import org.datanucleus.store.rdbms.sql.method.SQLMethod;
import org.dependencytrack.model.Project;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @since 5.6.0
 */
public class ProjectIsAccessibleByMethod implements SQLMethod {

    @Override
    public SQLExpression getExpression(
            final SQLStatement stmt,
            final SQLExpression expr,
            final List<SQLExpression> args) {
        final ObjectExpression objectExpr = validateType(expr, ObjectExpression.class);

        final String objectTypeName = objectExpr.getJavaTypeMapping().getType();
        if (!Project.class.getName().equals(objectTypeName))
            throw new IllegalStateException(
                    "isAccessibleBy is only allowed for objects of type %s, but was called on %s".formatted(
                            Project.class.getName(), objectTypeName));

        // TODO: When a list, set, etc. is passed as argument, it will be of type CollectionLiteral.
        //  Array literals are easier to verify the type of, hence we're focusing on that for now.
        switch (args) {
            case List<SQLExpression> a when a == null || a.isEmpty() -> throw new IllegalArgumentException();
            case List<SQLExpression> a when a.size() == 1 -> {
                final ArrayLiteral arrayLiteralArg = validateType(args.getFirst(), ArrayLiteral.class);

                return getApiKeyExpression(stmt, objectExpr, arrayLiteralArg);
            }
            case List<SQLExpression> a when a.size() == 2 -> {
                final IntegerLiteral userIdArg = validateType(args.getFirst(), IntegerLiteral.class);
                final ArrayLiteral arrayLiteralArg = validateType(args.getLast(), ArrayLiteral.class);

                return getUserExpression(stmt, objectExpr, userIdArg, arrayLiteralArg);
            }
            default -> throw new IllegalArgumentException("Expected one or two arguments, but got " + args.size());
        }
    }

    private SQLExpression getApiKeyExpression(final SQLStatement stmt, final ObjectExpression objectExpr, final ArrayLiteral arrayLiteralArg) {
        final Long[] teamIds = validateType(arrayLiteralArg.getValue(), Long[].class);

        final JavaTypeMapping booleanTypeMapping = getTypeMapping(stmt, Boolean.class);
        final JavaTypeMapping stringTypeMapping = getTypeMapping(stmt, String.class);

        // Transform the array literal to have the correct type for Postgres.
        // Will result in the following expression: cast('{1,2,3}' as bigint[])
        final String arrayString = Stream.of(teamIds).map(String::valueOf).collect(Collectors.joining(",", "{", "}"));
        final StringLiteral arrayLiteral = new StringLiteral(stmt, stringTypeMapping, arrayString, null);
        final StringExpression castExpr = new StringExpression(
                stmt, stringTypeMapping, "cast", List.of(arrayLiteral), List.of("bigint[]"));

        // TODO: This should not rely on a SQL function, as functions yield a
        //  suboptimal query plan (https://github.com/DependencyTrack/hyades/issues/1801).
        //  Instead, a SQLExpression equivalent to the function content should be assembled.

        // NB: objectExpr will compile to a reference of the object table's ID column, e.g.:
        //   * "A0"."ID"
        //   * "B0"."PROJECT_ID"
        final StringExpression functionExpr = new StringExpression(
                stmt, stringTypeMapping, "has_project_access", List.of(objectExpr, castExpr));

        // Wrap the function call in a boolean expression. Final result(s) will be:
        //   * has_project_access("A0"."ID", cast('{1,2,3}' as bigint[])) = TRUE
        //   * has_project_access("B0"."PROJECT_ID", cast('{1,2,3}' as bigint[])) = TRUE
        final BooleanLiteral booleanTrueLiteral = new BooleanLiteral(stmt, booleanTypeMapping, Boolean.TRUE, null);

        return new BooleanExpression(functionExpr, Expression.OP_EQ, booleanTrueLiteral);
    }

    private SQLExpression getUserExpression(final SQLStatement stmt, final ObjectExpression objectExpr, final IntegerLiteral userIdArg, final ArrayLiteral arrayLiteralArg) {
        final Long userId = validateType(userIdArg.getValue(), Long.class);
        final String[] permissions = validateType(arrayLiteralArg.getValue(), String[].class);

        final JavaTypeMapping booleanTypeMapping = getTypeMapping(stmt, Boolean.class);
        final JavaTypeMapping integerTypeMapping = getTypeMapping(stmt, Long.class);
        final JavaTypeMapping stringTypeMapping = getTypeMapping(stmt, String.class);

        final IntegerLiteral userIdLiteral = new IntegerLiteral(stmt, integerTypeMapping, userId, "userId");

        // Transform the array literal to have the correct type for Postgres.
        // Will result in the following expression: cast('{one,two,three}' as text[])
        final String arrayString = Stream.of(permissions).collect(Collectors.joining(",", "{", "}"));
        final StringLiteral arrayLiteral = new StringLiteral(stmt, stringTypeMapping, arrayString, null);
        final StringExpression castExpr = new StringExpression(
                stmt, stringTypeMapping, "cast", List.of(arrayLiteral), List.of("text[]"));

        // NB: objectExpr will compile to a reference of the object table's ID column, e.g.:
        //   * "A0"."ID"
        //   * "B0"."PROJECT_ID"
        final StringExpression functionExpr = new StringExpression(
                stmt, stringTypeMapping, "has_user_project_access", List.of(objectExpr, userIdLiteral, castExpr));

        // Wrap the function call in a boolean expression. Final result(s) will be:
        //   * has_user_project_access("A0"."ID", 1) = TRUE
        //   * has_user_project_access("B0"."PROJECT_ID", 1) = TRUE
        final BooleanLiteral booleanTrueLiteral = new BooleanLiteral(stmt, booleanTypeMapping, Boolean.TRUE, null);

        return new BooleanExpression(functionExpr, Expression.OP_EQ, booleanTrueLiteral);
    }

    private JavaTypeMapping getTypeMapping(final SQLStatement stmt, final Class<?> type) {
        return stmt.getSQLExpressionFactory().getMappingForType(type);
    }

    @SuppressWarnings("unchecked")
    private <T> T validateType(final Object arg, final Class<T> expected) {
        final String argType = arg instanceof SQLLiteral ? "argument" : "expression";

        if (!expected.isInstance(arg))
            throw new IllegalArgumentException("Expected %s to be of type %s, but got %s"
                    .formatted(argType, expected.getName(), arg.getClass().getName()));

        return (T) arg;
    }

}
