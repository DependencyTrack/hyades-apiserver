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
import org.projectnessie.cel.Ast;
import org.projectnessie.cel.CEL;
import org.projectnessie.cel.Env;
import org.projectnessie.cel.common.types.Err;

import java.util.Map;

public class SearchExpressionEvaluator {

    private final Env env;
    private final Map<String, String> fieldMappings;

    public SearchExpressionEvaluator(final Env env, final Map<String, String> fieldMappings) {
        this.env = env;
        this.fieldMappings = fieldMappings;
    }

    public record EvaluationResult(String sqlCondition, Map<String, Object> queryParams) {
    }

    public EvaluationResult evaluate(final String expression) {
        Env.AstIssuesTuple astIssuesTuple = env.parse(expression);
        if (astIssuesTuple.hasIssues()) {
            throw new IllegalStateException("Failed to parse expression: " + astIssuesTuple.getIssues());
        }

        try {
            astIssuesTuple = env.check(astIssuesTuple.getAst());
        } catch (Err.ErrException e) {
            throw new IllegalStateException("Failed to check expression", e);
        }
        if (astIssuesTuple.hasIssues()) {
            throw new IllegalArgumentException("Failed to check expression: " + astIssuesTuple.getIssues());
        }

        final Ast ast = astIssuesTuple.getAst();
        final CheckedExpr checkedExpr = CEL.astToCheckedExpr(ast);

        final var visitor = new SearchExpressionVisitor(fieldMappings, checkedExpr);
        visitor.visit(checkedExpr.getExpr());

        return new EvaluationResult(
                visitor.getQuery(),
                visitor.getQueryParams());
    }

}
