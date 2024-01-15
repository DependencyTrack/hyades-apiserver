package org.dependencytrack.policy.cel;

import alpine.common.logging.Logger;
import com.google.api.expr.v1alpha1.Constant;
import com.google.api.expr.v1alpha1.Expr;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.dependencytrack.proto.policy.v1.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

class CelPolicyScriptVersValidationVisitor {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyScriptVersValidationVisitor.class);
    private static final Set<String> COMPONENT_FILTER_FIELDS = Set.of("group", "name", "classifier", "cpe", "purl", "swid_tag_id");
    private static final List<String> COMPONENT_FILTER_FIELDS_SORTED = COMPONENT_FILTER_FIELDS.stream().sorted().toList();

    record VersValidationError(RuntimeException exception, Integer position) {
    }

    private final Map<Long, Integer> positions;
    private final List<VersValidationError> errors;

    CelPolicyScriptVersValidationVisitor(final Map<Long, Integer> positions) {
        this.positions = positions;
        this.errors = new ArrayList<>();
    }

    void visit(final Expr expr) {
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
        if ("matches_range".equals(callExpr.getFunction())) {
            maybeValidateVers(callExpr.getArgs(0));
            return;
        } else if (("depends_on".equals(callExpr.getFunction()) || "is_dependency_of".equals(callExpr.getFunction())) && callExpr.getArgsCount() == 1) {
            maybeValidateComponentStruct(callExpr.getArgs(0));
            return;
        }

        visit(callExpr.getTarget());
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

    private void maybeValidateComponentStruct(final Expr expr) {
        if (expr.getExprKindCase() != Expr.ExprKindCase.STRUCT_EXPR) {
            // Should've been catched in type checking phase.
            return;
        }

        final Expr.CreateStruct structExpr = expr.getStructExpr();
        if (!Component.getDescriptor().getFullName().equals(structExpr.getMessageName())) {
            // Should've been catched in type checking phase.
            return;
        }

        Expr.CreateStruct.Entry versionEntryExpr = null;
        boolean hasQualifiers = false;
        for (final Expr.CreateStruct.Entry structEntryExpr : structExpr.getEntriesList()) {
            if ("version".equals(structEntryExpr.getFieldKey())) {
                versionEntryExpr = structEntryExpr;
            } else if (COMPONENT_FILTER_FIELDS.contains(structEntryExpr.getFieldKey())) {
                hasQualifiers = true;
            }
        }
        if (versionEntryExpr == null) {
            return;
        }

        final String version = versionEntryExpr.getValue().getConstExpr().getStringValue();
        if (!version.startsWith("vers:")) {
            // It's a version literal, nothing to validate here.
            return;
        }

        if (!hasQualifiers) {
            final var exception = new RuntimeException("""
                    Querying by version range without providing an additional field to filter on is not allowed. \
                    Possible fields to filter on are: %s""".formatted(COMPONENT_FILTER_FIELDS_SORTED));
            errors.add(new VersValidationError(exception, positions.get(expr.getId())));
        }

        maybeValidateVers(versionEntryExpr.getValue());
    }

    private void maybeValidateVers(final Expr expr) {
        if (expr.getExprKindCase() != Expr.ExprKindCase.CONST_EXPR) {
            return;
        }

        final Constant constExpr = expr.getConstExpr();
        if (constExpr.getConstantKindCase() != Constant.ConstantKindCase.STRING_VALUE) {
            return;
        }

        try {
            final Vers vers = Vers.parse(constExpr.getStringValue());
            vers.validate();
        } catch (VersException e) {
            errors.add(new VersValidationError(e, positions.get(expr.getId())));
        }
    }

    List<VersValidationError> getErrors() {
        return Collections.unmodifiableList(errors);
    }

}
