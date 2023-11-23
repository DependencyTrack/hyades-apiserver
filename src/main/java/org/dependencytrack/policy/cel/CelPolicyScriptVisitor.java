package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.google.api.expr.v1alpha1.Expr;
import com.google.api.expr.v1alpha1.Type;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.projectnessie.cel.common.CELError;
import org.projectnessie.cel.common.Errors;
import org.projectnessie.cel.common.Location;
import org.projectnessie.cel.tools.ScriptCreateException;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.api.expr.v1alpha1.Expr.ExprKindCase.CONST_EXPR;
import static org.projectnessie.cel.Issues.newIssues;
import static org.projectnessie.cel.common.Source.newTextSource;

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

    public void visitVersRangeCheck(final Expr expr) throws ScriptCreateException {
        final var callExpr = expr.getCallExpr();
        if (!callExpr.getArgsList().isEmpty()
                && callExpr.getArgsList().get(0).getExprKindCase() == CONST_EXPR) {
            var versArg = callExpr.getArgsList().get(0).getConstExpr().getStringValue();
            try {
                Vers.parse(versArg);
            } catch (VersException e) {
                throw new ScriptCreateException("Failed to parse the vers range ", newIssues(new Errors(newTextSource(versArg))
                        .append(Collections.singletonList(
                                new CELError(e, Location.newLocation(1, 1), e.getMessage())
                        ))
                ));
            }
        }
    }

    private void logExpr(final Expr expr) {
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
