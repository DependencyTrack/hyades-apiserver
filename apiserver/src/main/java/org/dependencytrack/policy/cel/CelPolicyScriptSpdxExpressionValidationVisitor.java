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
package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.google.api.expr.v1alpha1.Constant;
import com.google.api.expr.v1alpha1.Expr;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParser;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_SPDX_EXPR_ALLOWS;
import static org.dependencytrack.policy.cel.CelCommonPolicyLibrary.FUNC_SPDX_EXPR_REQUIRES_ANY;

/**
 * @since 5.7.0
 */
final class CelPolicyScriptSpdxExpressionValidationVisitor {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyScriptSpdxExpressionValidationVisitor.class);
    private static final SpdxExpressionParser PARSER = new SpdxExpressionParser();

    static final Set<String> RELEVANT_FUNCTIONS = Set.of(
            FUNC_SPDX_EXPR_ALLOWS,
            FUNC_SPDX_EXPR_REQUIRES_ANY);

    record SpdxExpressionValidationError(String message, Integer position) {
    }

    private final Map<Long, Integer> positions;
    private final List<SpdxExpressionValidationError> errors;
    private final boolean isApplicable;

    CelPolicyScriptSpdxExpressionValidationVisitor(
            Map<Long, Integer> positions,
            Set<String> usedFunctions) {
        this.positions = positions;
        this.errors = new ArrayList<>();
        this.isApplicable = usedFunctions.stream().anyMatch(RELEVANT_FUNCTIONS::contains);
    }

    void visit(final Expr expr) {
        if (!isApplicable) {
            return;
        }

        switch (expr.getExprKindCase()) {
            case CALL_EXPR -> visitCall(expr);
            case COMPREHENSION_EXPR -> visitComprehension(expr);
            case LIST_EXPR -> visitList(expr);
            case SELECT_EXPR -> visitSelect(expr);
            case EXPRKIND_NOT_SET -> LOGGER.debug("Unknown expression: %s".formatted(expr));
        }
    }

    private void visitCall(final Expr expr) {
        final Expr.Call callExpr = expr.getCallExpr();
        final String functionName = callExpr.getFunction();

        if (RELEVANT_FUNCTIONS.contains(functionName)) {
            if (callExpr.getArgsCount() > 0) {
                maybeValidateSpdxExpression(callExpr.getArgs(0));
            }

            for (final Expr argExpr : callExpr.getArgsList()) {
                visit(argExpr);
            }

            return;
        }

        if (callExpr.hasTarget()) {
            visit(callExpr.getTarget());
        }

        for (final Expr argExpr : callExpr.getArgsList()) {
            visit(argExpr);
        }
    }

    private void visitComprehension(final Expr expr) {
        final Expr.Comprehension comprehensionExpr = expr.getComprehensionExpr();
        visit(comprehensionExpr.getAccuInit());
        visit(comprehensionExpr.getIterRange());
        visit(comprehensionExpr.getLoopStep());
        visit(comprehensionExpr.getLoopCondition());
        visit(comprehensionExpr.getResult());
    }

    private void visitList(final Expr expr) {
        final Expr.CreateList listExpr = expr.getListExpr();
        for (final Expr elementExpr : listExpr.getElementsList()) {
            visit(elementExpr);
        }
    }

    private void visitSelect(final Expr expr) {
        final Expr.Select selectExpr = expr.getSelectExpr();
        visit(selectExpr.getOperand());
    }

    private void maybeValidateSpdxExpression(final Expr expr) {
        if (expr.getExprKindCase() != Expr.ExprKindCase.CONST_EXPR) {
            return;
        }

        final Constant constExpr = expr.getConstExpr();
        if (constExpr.getConstantKindCase() != Constant.ConstantKindCase.STRING_VALUE) {
            return;
        }

        final String value = constExpr.getStringValue();
        final SpdxExpression parsed = PARSER.parse(value);
        if (parsed == SpdxExpression.INVALID) {
            errors.add(
                    new SpdxExpressionValidationError(
                            "Invalid SPDX expression: \"%s\"".formatted(value),
                            positions.get(expr.getId())));
        }
    }

    List<SpdxExpressionValidationError> getErrors() {
        return Collections.unmodifiableList(errors);
    }

}
