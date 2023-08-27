package org.dependencytrack.parser.vers;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public record Constraint(Comparator comparator, String version) {

    public Constraint {
        if (comparator == null) {
            throw new VersException("comparator must not be null");
        }
        if (comparator == Comparator.WILDCARD && version != null) {
            throw new VersException("comparator %s is not allowed with version".formatted(comparator));
        } else if (comparator != Comparator.WILDCARD && version == null) {
            throw new VersException("comparator %s is not allowed without version".formatted(comparator));
        }
    }

    static Constraint parse(final String constraintStr) {
        final Comparator comparator;
        if (constraintStr.startsWith("<=")) {
            comparator = Comparator.LESS_THAN_OR_EQUAL;
        } else if (constraintStr.startsWith(">=")) {
            comparator = Comparator.GREATER_THAN_OR_EQUAL;
        } else if (constraintStr.startsWith("!=")) {
            comparator = Comparator.NOT_EQUAL;
        } else if (constraintStr.startsWith("<")) {
            comparator = Comparator.LESS_THAN;
        } else if (constraintStr.startsWith(">")) {
            comparator = Comparator.GREATER_THAN;
        } else {
            comparator = Comparator.EQUAL;
        }

        final String versionStr = constraintStr.replaceFirst("^" + Pattern.quote(comparator.operator()), "").trim();
        if (versionStr.isBlank()) {
            throw new VersException("comparator %s is not allowed without version".formatted(comparator));
        }

        return new Constraint(comparator, maybeUrlDecode(versionStr));
    }

    private static String maybeUrlDecode(final String version) {
        if (version.contains("%")) {
            return URLDecoder.decode(version, StandardCharsets.UTF_8);
        }

        return version;
    }

    @Override
    public String toString() {
        if (comparator == Comparator.WILDCARD) {
            // Wildcard cannot have a version.
            return Comparator.WILDCARD.operator();
        }

        if (comparator == Comparator.EQUAL) {
            // Operator is omitted for equality.
            return URLEncoder.encode(version(), StandardCharsets.UTF_8);
        }

        return comparator.operator() + URLEncoder.encode(version, StandardCharsets.UTF_8);
    }

}
