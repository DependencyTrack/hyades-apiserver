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

import com.google.api.expr.v1alpha1.Expr;

public interface CelExpressionVisitor {

    default void visit(Expr expr) {
        switch (expr.getExprKindCase()) {
            case CALL_EXPR -> visitCall(expr);
            case COMPREHENSION_EXPR -> visitComprehension(expr);
            case CONST_EXPR -> visitConst(expr);
            case IDENT_EXPR -> visitIdent(expr);
            case LIST_EXPR -> visitList(expr);
            case SELECT_EXPR -> visitSelect(expr);
            case STRUCT_EXPR -> visitStruct(expr);
            case EXPRKIND_NOT_SET -> visitUnknown(expr);
        }
    }

    default void visitCall(final Expr expr) {
    }

    default void visitComprehension(final Expr expr) {
    }

    default void visitConst(final Expr expr) {
    }

    default void visitIdent(final Expr expr) {
    }

    default void visitList(final Expr expr) {
    }

    default void visitSelect(final Expr expr) {
    }

    default void visitStruct(final Expr expr) {
    }

    default void visitUnknown(final Expr expr) {
    }

}
