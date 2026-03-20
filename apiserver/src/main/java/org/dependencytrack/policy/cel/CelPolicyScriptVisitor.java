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

import com.google.api.expr.v1alpha1.Expr;
import com.google.api.expr.v1alpha1.Type;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class CelPolicyScriptVisitor {

    record FunctionSignature(String function, Type targetType, List<Type> argumentTypes) {
    }

    private final Map<Long, Type> typeByExpressionId;
    private final MultiValuedMap<Type, String> accessedFieldsByType;
    private final Set<FunctionSignature> usedFunctionSignatures;

    CelPolicyScriptVisitor(Map<Long, Type> typeByExpressionId) {
        this.typeByExpressionId = typeByExpressionId;
        this.accessedFieldsByType = new HashSetValuedHashMap<>();
        this.usedFunctionSignatures = new HashSet<>();
    }

    void visit(Expr expr) {
        switch (expr.getExprKindCase()) {
            case CALL_EXPR -> visitCall(expr);
            case COMPREHENSION_EXPR -> visitComprehension(expr);
            case LIST_EXPR -> visitList(expr);
            case SELECT_EXPR -> visitSelect(expr);
            case STRUCT_EXPR -> visitStruct(expr);
            case CONST_EXPR, EXPRKIND_NOT_SET, IDENT_EXPR -> {
            }
        }
    }

    private void visitCall(Expr expr) {
        final Expr.Call callExpr = expr.getCallExpr();

        final Type targetType = typeByExpressionId.get(callExpr.getTarget().getId());
        final List<Type> argumentTypes = callExpr.getArgsList().stream()
                .map(Expr::getId)
                .map(typeByExpressionId::get)
                .toList();
        usedFunctionSignatures.add(new FunctionSignature(callExpr.getFunction(), targetType, argumentTypes));

        visit(callExpr.getTarget());
        callExpr.getArgsList().forEach(this::visit);
    }

    private void visitComprehension(Expr expr) {
        final Expr.Comprehension comprehensionExpr = expr.getComprehensionExpr();

        visit(comprehensionExpr.getAccuInit());
        visit(comprehensionExpr.getIterRange());
        visit(comprehensionExpr.getLoopStep());
        visit(comprehensionExpr.getLoopCondition());
        visit(comprehensionExpr.getResult());
    }

    private void visitList(Expr expr) {
        expr.getListExpr().getElementsList().forEach(this::visit);
    }

    private void visitSelect(Expr expr) {
        final Expr.Select selectExpr = expr.getSelectExpr();
        final Type operandType = typeByExpressionId.get(selectExpr.getOperand().getId());
        if (operandType != null) {
            accessedFieldsByType.put(operandType, selectExpr.getField());
        }
        visit(selectExpr.getOperand());
    }

    private void visitStruct(Expr expr) {
        expr.getStructExpr().getEntriesList().forEach(entry -> {
            if (entry.hasMapKey()) {
                visit(entry.getMapKey());
            }
            visit(entry.getValue());
        });
    }

    MultiValuedMap<Type, String> getAccessedFieldsByType() {
        return this.accessedFieldsByType;
    }

    Set<FunctionSignature> getUsedFunctionSignatures() {
        return this.usedFunctionSignatures;
    }

}
