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
import com.google.api.expr.v1alpha1.Expr;
import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class CelPolicyScriptVisitor {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyScriptVisitor.class);

    record FunctionSignature(String function, Type targetType, List<Type> argumentTypes) {
    }

    private final Map<Long, Type> types;
    private final MultiValuedMap<Type, String> accessedFieldsByType;
    private final Set<FunctionSignature> usedFunctionSignatures;
    private final Deque<String> callFunctionStack;
    private final Deque<String> selectFieldStack;
    private final Deque<Type> selectOperandTypeStack;

    CelPolicyScriptVisitor(final Map<Long, Type> types) {
        this.types = types;
        this.accessedFieldsByType = new HashSetValuedHashMap<>();
        this.usedFunctionSignatures = new HashSet<>();
        this.callFunctionStack = new ArrayDeque<>();
        this.selectFieldStack = new ArrayDeque<>();
        this.selectOperandTypeStack = new ArrayDeque<>();
    }

    void visit(final Expr expr) {
        switch (expr.getExprKindCase()) {
            case CALL_EXPR -> visitCall(expr);
            case COMPREHENSION_EXPR -> visitComprehension(expr);
            case CONST_EXPR -> visitConst(expr);
            case IDENT_EXPR -> visitIdent(expr);
            case LIST_EXPR -> visitList(expr);
            case SELECT_EXPR -> visitSelect(expr);
            case STRUCT_EXPR -> visitStruct(expr);
            case EXPRKIND_NOT_SET -> LOGGER.debug("Unknown expression: %s".formatted(expr));
        }
    }

    private void visitCall(final Expr expr) {
        logExpr(expr);
        final Expr.Call callExpr = expr.getCallExpr();

        final Type targetType = types.get(callExpr.getTarget().getId());
        final List<Type> argumentTypes = callExpr.getArgsList().stream()
                .map(Expr::getId)
                .map(types::get)
                .toList();
        usedFunctionSignatures.add(new FunctionSignature(callExpr.getFunction(), targetType, argumentTypes));

        callFunctionStack.push(callExpr.getFunction());
        visit(callExpr.getTarget());
        for (final Expr argExpr : callExpr.getArgsList()) {
            visit(argExpr);
        }
        callFunctionStack.pop();
    }

    private void visitComprehension(final Expr expr) {
        logExpr(expr);
        final Expr.Comprehension comprehensionExpr = expr.getComprehensionExpr();

        visit(comprehensionExpr.getAccuInit());
        visit(comprehensionExpr.getIterRange());
        visit(comprehensionExpr.getLoopStep());
        visit(comprehensionExpr.getLoopCondition());
        visit(comprehensionExpr.getResult());
    }

    private void visitConst(final Expr expr) {
        logExpr(expr);
    }

    private void visitIdent(final Expr expr) {
        logExpr(expr);
        selectOperandTypeStack.push(types.get(expr.getId()));
    }

    private void visitList(final Expr expr) {
        logExpr(expr);
    }

    private void visitSelect(final Expr expr) {
        logExpr(expr);
        final Expr.Select selectExpr = expr.getSelectExpr();

        selectFieldStack.push(selectExpr.getField());
        selectOperandTypeStack.push(types.get(expr.getId()));
        visit(selectExpr.getOperand());
        accessedFieldsByType.put(selectOperandTypeStack.pop(), selectFieldStack.pop());
    }

    private void visitStruct(final Expr expr) {
        logExpr(expr);
    }

    private void logExpr(final Expr expr) {
        if (!LOGGER.isDebugEnabled()) {
            return;
        }

        LOGGER.debug("Visiting %s (id=%d, fieldStack=%s, fieldTypeStack=%s, functionStack=%s)"
                .formatted(expr.getExprKindCase(), expr.getId(), selectFieldStack, selectOperandTypeStack, callFunctionStack));
    }

    MultiValuedMap<Type, String> getAccessedFieldsByType() {
        return this.accessedFieldsByType;
    }

    Set<FunctionSignature> getUsedFunctionSignatures() {
        return this.usedFunctionSignatures;
    }

}
