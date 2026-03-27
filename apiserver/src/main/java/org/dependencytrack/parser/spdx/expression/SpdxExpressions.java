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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * @since 5.7.0
 */
public final class SpdxExpressions {

    private SpdxExpressions() {
    }

    public static boolean allows(String expression, List<String> ids) {
        final SpdxExpression parsed = SpdxExpressionParser.getInstance().parse(expression);
        if (parsed == SpdxExpression.INVALID) {
            return false;
        }

        return allows(parsed, buildAllowsMatcher(ids));
    }

    public static boolean requiresAny(String expression, List<String> ids) {
        final SpdxExpression parsed = SpdxExpressionParser.getInstance().parse(expression);
        if (parsed == SpdxExpression.INVALID) {
            return false;
        }

        return requires(parsed, buildRequiresMatcher(ids));
    }

    private static Predicate<SpdxExpression> buildAllowsMatcher(List<String> ids) {
        final List<SpdxLicenseId> leafEntries = new ArrayList<>();
        final List<SpdxExpression> withComposites = new ArrayList<>();

        for (final String id : ids) {
            final SpdxExpression parsed = SpdxExpressionParser.getInstance().parse(id);
            if (parsed == SpdxExpression.INVALID) {
                leafEntries.add(SpdxLicenseId.of(id));
                continue;
            }

            final SpdxLicenseId licenseId = SpdxLicenseId.of(parsed);
            if (licenseId != null) {
                leafEntries.add(licenseId);
            } else if (parsed.getOperation() != null
                    && parsed.getOperation().getOperator() == SpdxOperator.WITH) {
                withComposites.add(parsed);
            }
        }

        return expr -> {
            final SpdxLicenseId exprId = SpdxLicenseId.of(expr);

            if (exprId != null) {
                return leafEntries.stream().anyMatch(exprId::isCompatibleWith);
            }

            if (expr.getOperation() != null
                    && expr.getOperation().getOperator() == SpdxOperator.WITH) {
                return withComposites.stream().anyMatch(
                        allowed -> withCompositeMatches(expr, allowed));
            }

            return false;
        };
    }

    private static Predicate<SpdxExpression> buildRequiresMatcher(List<String> ids) {
        final List<SpdxLicenseId> leafEntries = new ArrayList<>();
        final List<SpdxExpression> withComposites = new ArrayList<>();

        for (final String id : ids) {
            final SpdxExpression parsed = SpdxExpressionParser.getInstance().parse(id);
            if (parsed == SpdxExpression.INVALID) {
                leafEntries.add(SpdxLicenseId.of(id));
                continue;
            }

            final SpdxLicenseId licenseId = SpdxLicenseId.of(parsed);
            if (licenseId != null) {
                leafEntries.add(licenseId);
            } else if (parsed.getOperation() != null
                    && parsed.getOperation().getOperator() == SpdxOperator.WITH) {
                withComposites.add(parsed);
            }
        }

        return expr -> {
            final SpdxLicenseId exprId = SpdxLicenseId.of(expr);
            if (exprId != null) {
                return leafEntries.stream().anyMatch(exprId::isEquivalentTo);
            }

            if (expr.getOperation() != null
                    && expr.getOperation().getOperator() == SpdxOperator.WITH) {
                return withComposites.stream().anyMatch(
                        allowed -> withCompositeMatches(expr, allowed));
            }

            return false;
        };
    }

    private static boolean withCompositeMatches(SpdxExpression expr, SpdxExpression allowed) {
        final SpdxExpressionOperation exprOp = expr.getOperation();
        final SpdxExpressionOperation allowedOp = allowed.getOperation();

        if (exprOp == null
                || allowedOp == null
                || exprOp.getOperator() != SpdxOperator.WITH
                || allowedOp.getOperator() != SpdxOperator.WITH
                || exprOp.getArguments().size() != 2
                || allowedOp.getArguments().size() != 2) {
            return false;
        }

        final SpdxLicenseId exprLicense = SpdxLicenseId.of(exprOp.getArguments().getFirst());
        final String exprException = exprOp.getArguments().get(1).getSpdxLicenseId();

        final SpdxLicenseId allowedLicense = SpdxLicenseId.of(allowedOp.getArguments().getFirst());
        final String allowedException = allowedOp.getArguments().get(1).getSpdxLicenseId();

        if (exprLicense == null
                || allowedLicense == null
                || exprException == null || allowedException == null) {
            return false;
        }

        return exprLicense.isCompatibleWith(allowedLicense)
                && exprException.equalsIgnoreCase(allowedException);
    }

    private static boolean allows(SpdxExpression expr, Predicate<SpdxExpression> isAllowed) {
        if (expr.getSpdxLicenseId() != null) {
            return isAllowed.test(expr);
        }

        final SpdxExpressionOperation op = expr.getOperation();
        if (op == null) {
            return false;
        }

        // WITH and PLUS are atomic composites. Match the whole node, not children.
        if (op.getOperator() == SpdxOperator.WITH || op.getOperator() == SpdxOperator.PLUS) {
            return isAllowed.test(expr);
        }

        if (op.getOperator() == SpdxOperator.OR) {
            return op.getArguments().stream().anyMatch(arg -> allows(arg, isAllowed));
        }

        // AND: all children must be satisfiable.
        return op.getArguments().stream().allMatch(arg -> allows(arg, isAllowed));
    }

    private static boolean requires(SpdxExpression expr, Predicate<SpdxExpression> isRequired) {
        if (expr.getSpdxLicenseId() != null) {
            return isRequired.test(expr);
        }

        final SpdxExpressionOperation op = expr.getOperation();
        if (op == null) {
            return false;
        }

        // WITH is an atomic composite, meaning the whole license-with-exception is the obligation.
        if (op.getOperator() == SpdxOperator.WITH) {
            return isRequired.test(expr);
        }

        // PLUS(X) means "X or any later version". Only the base version X is guaranteed,
        // so recurse into the child rather than matching the or-later range.
        if (op.getOperator() == SpdxOperator.PLUS) {
            return op.getArguments().stream().anyMatch(arg -> requires(arg, isRequired));
        }

        if (op.getOperator() == SpdxOperator.OR) {
            return op.getArguments().stream().allMatch(arg -> requires(arg, isRequired));
        }

        // AND: required if any child requires it.
        return op.getArguments().stream().anyMatch(arg -> requires(arg, isRequired));
    }

}
