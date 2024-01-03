package org.dependencytrack.util;

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;

import java.util.Optional;

public final class AnalysisCommentFormatter {

    public enum AnalysisCommentField {

        STATE("State", AnalysisState.NOT_SET.name()),
        JUSTIFICATION("Justification", AnalysisJustification.NOT_SET.name()),
        RESPONSE("Response", AnalysisResponse.NOT_SET.name()),
        DETAILS("Details", "(None)"),
        SUPPRESSED(null, null),
        SEVERITY("Severity", Severity.UNASSIGNED.name()),
        CVSSV2_VECTOR("CVSSv2 Vector", "(None)"),
        CVSSV2_SCORE("CVSSv2 Score", "(None)"),
        CVSSV3_VECTOR("CVSSv3 Vector", "(None)"),
        CVSSV3_SCORE("CVSSv3 Score", "(None)"),
        OWASP_VECTOR("OWASP Vector", "(None)"),
        OWASP_SCORE("OWASP Score", "(None)");

        private final String displayName;
        private final String nullValue;

        AnalysisCommentField(final String displayName, final String nullValue) {
            this.displayName = displayName;
            this.nullValue = nullValue;
        }

    }

    private AnalysisCommentFormatter() {
    }

    public static String formatComment(final AnalysisCommentField field, final Object oldValue, final Object newValue) {
        if (field == AnalysisCommentField.SUPPRESSED) {
            final String oldValueString = (oldValue instanceof final Boolean oldValueBoolean && oldValueBoolean) ? "Suppressed" : "Unsuppressed";
            final String newValueString = (newValue instanceof final Boolean newValueBoolean && newValueBoolean) ? "Suppressed" : "Unsuppressed";
            return "%s → %s".formatted(oldValueString, newValueString);
        }

        final String oldValueString = Optional.ofNullable(oldValue).map(Object::toString).orElse(field.nullValue);
        final String newValueString = Optional.ofNullable(newValue).map(Object::toString).orElse(field.nullValue);
        return "%s: %s → %s".formatted(field.displayName, oldValueString, newValueString);
    }

}
