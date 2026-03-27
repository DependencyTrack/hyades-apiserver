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
package org.dependencytrack.parser.spdx.expression;

import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpressionOperation;
import org.dependencytrack.parser.spdx.expression.model.SpdxOperator;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * This class parses SPDX expressions according to
 * https://spdx.github.io/spdx-spec/v2-draft/SPDX-license-expressions/ into a tree of
 * SpdxExpressions and SpdxExpressionOperations
 *
 * @author hborchardt
 * @since 4.9.0
 */
public final class SpdxExpressionParser {

    private static final SpdxExpressionParser INSTANCE = new SpdxExpressionParser();

    private SpdxExpressionParser() {
    }

    public static SpdxExpressionParser getInstance() {
        return INSTANCE;
    }

    /**
     * Reads in a SPDX expression and returns a parsed tree of SpdxExpressionOperators and license
     * ids.
     *
     * @param spdxExpression spdx expression string
     * @return parsed SpdxExpression tree, or SpdxExpression.INVALID if an error has occurred during
     * parsing
     */
    public SpdxExpression parse(final String spdxExpression) {
        try {
            return parseInternal(spdxExpression);
        } catch (RuntimeException e) {
            return SpdxExpression.INVALID;
        }
    }

    private SpdxExpression parseInternal(final String spdxExpression) {
        if (spdxExpression == null || spdxExpression.isBlank()) {
            return SpdxExpression.INVALID;
        }

        // operators are surrounded by spaces or brackets. Let's make our life easier and surround brackets by spaces.
        var _spdxExpression = spdxExpression.replace("(", " ( ").replace(")", " ) ").split(" ");

        // Shunting yard algorithm to convert SPDX expression to reverse polish notation
        // specify list of infix operators
        List<String> infixOperators = List.of(
                SpdxOperator.OR.getToken(),
                SpdxOperator.AND.getToken(),
                SpdxOperator.WITH.getToken());

        ArrayDeque<String> operatorStack = new ArrayDeque<>();
        ArrayDeque<String> outputQueue = new ArrayDeque<>();
        for (String token : List.of(_spdxExpression)) {
            if (token.isEmpty()) {
                continue;
            }
            if (infixOperators.contains(token)) {
                int opPrecedence = SpdxOperator.valueOf(token).getPrecedence();
                for (String o2; (o2 = operatorStack.peek()) != null && !o2.equals("(")
                        && SpdxOperator.valueOf(o2).getPrecedence() > opPrecedence; ) {
                    outputQueue.push(operatorStack.pop());
                }
                operatorStack.push(token);
            } else if (token.equals("(")) {
                operatorStack.push(token);
            } else if (token.equals(")")) {
                for (String o2; (o2 = operatorStack.peek()) == null || !o2.equals("("); ) {
                    if (o2 == null) {
                        // Mismatched parentheses
                        return SpdxExpression.INVALID;
                    }
                    outputQueue.push(operatorStack.pop());
                }
                String leftParens = operatorStack.pop();

                if (!"(".equals(leftParens)) {
                    // Mismatched parentheses
                    return SpdxExpression.INVALID;
                }
                // no function tokens implemented
            } else {
                outputQueue.push(token);
            }
        }
        for (String o2; (o2 = operatorStack.peek()) != null; ) {
            if ("(".equals(o2)) {
                // Mismatched parentheses
                return SpdxExpression.INVALID;
            }
            outputQueue.push(operatorStack.pop());
        }

        // Convert RPN stack into tree.
        ArrayDeque<SpdxExpression> expressions = new ArrayDeque<>();
        while (!outputQueue.isEmpty()) {
            var token = outputQueue.pollLast();
            if (infixOperators.contains(token)) {
                if (expressions.size() < 2) {
                    return SpdxExpression.INVALID;
                }
                var rhs = expressions.pop();
                var lhs = expressions.pop();
                final var operator = SpdxOperator.valueOf(token);
                if (operator == SpdxOperator.AND || operator == SpdxOperator.OR) {
                    // Flatten associative chains and sort for commutativity.
                    final var operands = new ArrayList<SpdxExpression>();
                    collectOperands(lhs, operator, operands);
                    collectOperands(rhs, operator, operands);
                    operands.sort(Comparator.comparing(SpdxExpression::toString, String.CASE_INSENSITIVE_ORDER));
                    expressions.push(new SpdxExpression(operator, List.copyOf(operands)));
                } else {
                    expressions.push(new SpdxExpression(operator, List.of(lhs, rhs)));
                }
            } else {
                if ("+".equals(token)) {
                    return SpdxExpression.INVALID;
                } else if (token.endsWith("+")) {
                    expressions.push(new SpdxExpression(
                            SpdxOperator.PLUS,
                            List.of(new SpdxExpression(token.substring(0, token.length() - 1)))));
                } else {
                    // Resolve deprecated WITH-compound IDs (e.g. GPL-2.0-with-classpath-exception)
                    // to their modern WITH expression equivalents.
                    final String resolved = SpdxLicenseRegistry.resolveWithCompound(token);
                    if (resolved != null) {
                        final SpdxExpression resolvedExpr = parse(resolved);
                        if (resolvedExpr == SpdxExpression.INVALID) {
                            return SpdxExpression.INVALID;
                        }
                        expressions.push(resolvedExpr);
                    } else {
                        expressions.push(new SpdxExpression(token));
                    }
                }
            }
        }
        if (expressions.size() != 1) {
            return SpdxExpression.INVALID;
        }

        return expressions.pop();
    }

    private static void collectOperands(SpdxExpression expr, SpdxOperator operator, List<SpdxExpression> out) {
        final SpdxExpressionOperation op = expr.getOperation();
        if (op != null && op.getOperator() == operator) {
            for (final SpdxExpression arg : op.getArguments()) {
                collectOperands(arg, operator, out);
            }
        } else {
            out.add(expr);
        }
    }

}