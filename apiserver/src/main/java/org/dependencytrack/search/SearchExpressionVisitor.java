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
package org.dependencytrack.search;

import com.google.api.expr.v1alpha1.CheckedExpr;
import com.google.api.expr.v1alpha1.Constant;
import com.google.api.expr.v1alpha1.Expr;
import com.google.api.expr.v1alpha1.Type;
import org.projectnessie.cel.common.operators.Operator;

import java.util.HashMap;
import java.util.Map;

public class SearchExpressionVisitor implements CelExpressionVisitor {

    private static final Map<Operator, String> SQL_BINARY_OPERATORS =
            Map.ofEntries(
                    Map.entry(Operator.LogicalAnd, "AND"),
                    Map.entry(Operator.LogicalOr, "OR"),
                    Map.entry(Operator.Equals, "="),
                    Map.entry(Operator.In, "IN"));
    private static final Map<Operator, String> SQL_UNARY_OPERATORS =
            Map.ofEntries(
                    Map.entry(Operator.LogicalNot, "NOT"));

    private final Map<String, String> fieldMappings;
    private final Map<Long, Type> typeByNodeId;
    private final Map<String, Object> queryParams = new HashMap<>();
    private final StringBuilder queryBuilder = new StringBuilder();
    private int queryParamIndex = 0;

    public SearchExpressionVisitor(
            final Map<String, String> fieldMappings,
            final CheckedExpr checkedExpr) {
        this.fieldMappings = fieldMappings;
        this.typeByNodeId = checkedExpr.getTypeMapMap();
    }

    public String getQuery() {
        return queryBuilder.toString();
    }

    public Map<String, Object> getQueryParams() {
        return Map.copyOf(queryParams);
    }

    @Override
    public void visitCall(final Expr expr) {
        final Expr.Call callExpr = expr.getCallExpr();

        final var operator = Operator.byId(callExpr.getFunction());
        switch (operator) {
            case Add,
                 Divide,
                 Equals,
                 Greater,
                 GreaterEquals,
                 In,
                 Less,
                 LessEquals,
                 LogicalAnd,
                 LogicalOr,
                 Multiply,
                 NotEquals,
                 OldIn,
                 Subtract -> visitCallBinary(callExpr, operator);
            case Conditional -> visitCallConditional(expr);
            case Index -> visitCallIndex(expr);
            case LogicalNot, Negate -> visitCallUnary(callExpr, operator);
            default -> visitCallFunction(expr);
        }
    }

    private void visitCallBinary(final Expr.Call callExpr, final Operator operator) {
        final Type lhsType = typeByNodeId.get(callExpr.getArgs(0).getId());
        final Type rhsType = typeByNodeId.get(callExpr.getArgs(1).getId());

        visit(callExpr.getArgs(0));

        final String sqlOperator;
        if (operator == Operator.Add
            && lhsType.getPrimitive() == Type.PrimitiveType.STRING
            && rhsType.getPrimitive() == Type.PrimitiveType.STRING) {
            sqlOperator = "||";
        } else if (operator == Operator.Equals
                   && (rhsType.hasNull() || rhsType.getPrimitive() == Type.PrimitiveType.BOOL)) {
            sqlOperator = "IS";
        } else if (operator == Operator.NotEquals
                   && (rhsType.hasNull() || rhsType.getPrimitive() == Type.PrimitiveType.BOOL)) {
            sqlOperator = "IS NOT";
        } else if (SQL_BINARY_OPERATORS.containsKey(operator)) {
            sqlOperator = SQL_BINARY_OPERATORS.get(operator);
        } else {
            throw new IllegalStateException("Unknown binary operator: " + operator);
        }

        queryBuilder.append(" ").append(sqlOperator).append(" ");

        visit(callExpr.getArgs(1));
    }

    private void visitCallConditional(final Expr expr) {
    }

    private void visitCallFunction(final Expr expr) {
    }

    private void visitCallIndex(final Expr expr) {

    }

    private void visitCallUnary(final Expr.Call callExpr, final Operator operator) {
        final String sqlOperator = SQL_UNARY_OPERATORS.get(operator);
        if (sqlOperator == null) {
            throw new IllegalStateException("Unknown unary operator: " + operator);
        }

        queryBuilder.append(sqlOperator).append(" ");
        visit(callExpr.getArgs(0));
    }

    @Override
    public void visitConst(final Expr expr) {
        final Constant constExpr = expr.getConstExpr();

        if (constExpr.hasNullValue()) {
            queryBuilder.append("NULL");
            return;
        }

        final String paramName = "param" + queryParamIndex++;
        queryBuilder.append(":").append(paramName);

        switch (constExpr.getConstantKindCase()) {
            case BOOL_VALUE -> queryParams.put(paramName, constExpr.getBoolValue());
            case INT64_VALUE -> queryParams.put(paramName, constExpr.getInt64Value());
            case STRING_VALUE -> queryParams.put(paramName, constExpr.getStringValue());
            default -> throw new IllegalStateException("Unexpected constant kind: " + constExpr.getConstantKindCase());
        }
    }

    @Override
    public void visitIdent(final Expr expr) {
        final Expr.Ident identExpr = expr.getIdentExpr();

        final String fieldExpression = fieldMappings.get(identExpr.getName());
        if (fieldExpression == null) {
            throw new IllegalStateException("No expression found for field: " + identExpr.getName());
        }

        queryBuilder.append(fieldExpression);
    }

}
