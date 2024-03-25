package org.dependencytrack.parser.vers;

import org.apache.commons.lang3.tuple.Pair;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public record Vers(String versioningScheme, List<Constraint> constraints) {

    public Vers {
        if (versioningScheme == null) {
            throw new VersException("versioning scheme must not be null");
        }
        if (constraints == null || constraints.isEmpty()) {
            throw new VersException("constraints must not be null or empty");
        }
    }

    public static Vers parse(final String versString) {
        if (versString == null || versString.isBlank()) {
            throw new VersException("vers string must not be null or blank");
        }

        String[] parts = versString.split(":", 2);
        if (parts.length != 2) {
            throw new VersException("vers string does not contain a URI scheme separator");
        }

        if (!"vers".equals(parts[0])) {
            throw new VersException("URI scheme must be \"vers\", but is \"%s\"".formatted(parts[0]));
        }

        parts = parts[1].split("/", 2);
        if (parts.length != 2) {
            throw new VersException("vers string does not contain a versioning scheme separator");
        }

        final String versioningScheme = parts[0];
        final String constraintsString = parts[1].replaceAll("^\\|+", "").replaceAll("\\|+$", "");
        if ("*".equals(constraintsString)) {
            return new Vers(versioningScheme, List.of(new Constraint(Comparator.WILDCARD, null)));
        }

        parts = constraintsString.split("\\|");
        if (parts.length == 0) {
            throw new VersException("vers string contains no constraints");
        }

        final List<Constraint> constraints = Arrays.stream(parts)
                .map(Constraint::parse)
                .toList();

        return new Vers(versioningScheme, constraints).validate();
    }

    public Vers validate() {
        // The special star "*" comparator matches any version.
        // It must be used alone exclusive of any other constraint and must not be followed by a version.
        // For example "vers:deb/*" represent all the versions of a Debian package.
        // This includes past, current and possible future versions.
        // https://github.com/package-url/purl-spec/blob/version-range-spec/VERSION-RANGE-SPEC.rst#version-constraint
        final boolean containsWildcard = constraints.stream()
                .map(Constraint::comparator)
                .anyMatch(Comparator.WILDCARD::equals);
        if (containsWildcard && constraints.size() > 1) {
            throw new VersException("comparator %s is only allowed with a single constraint".formatted(Comparator.WILDCARD));
        }

        // Ignoring all constraints with "!=" comparators...
        List<Constraint> tmpConstraints = constraints.stream()
                .filter(constraint -> constraint.comparator() != Comparator.NOT_EQUAL)
                .toList();
        if (tmpConstraints.size() < 2) {
            // Either no, or only one constraint remaining; Nothing to validate further.
            return this;
        }

        // A "=" constraint must be followed only by a constraint with one of "=", ">", ">=" as comparator (or no constraint).
        var constraintIter = new PairwiseIterator<>(tmpConstraints);
        while (constraintIter.hasNext()) {
            final Pair<Constraint, Constraint> constraintPair = constraintIter.next();
            final Constraint currConstraint = constraintPair.getLeft();
            final Constraint nextConstraint = constraintPair.getRight();

            if (currConstraint.comparator() == Comparator.EQUAL
                    && !Set.of(Comparator.EQUAL, Comparator.GREATER_THAN, Comparator.GREATER_THAN_OR_EQUAL).contains(nextConstraint.comparator())) {
                throw new VersException("A = comparator must only be followed by a > or >= operator, but got: %s".formatted(nextConstraint.comparator().operator()));
            }
        }

        // And ignoring all constraints with "=" or "!=" comparators...
        tmpConstraints = tmpConstraints.stream()
                .filter(constraint -> constraint.comparator() != Comparator.EQUAL)
                .toList();
        if (tmpConstraints.size() < 2) {
            // Either no, or only one constraint remaining; Nothing to validate further.
            return this;
        }

        // ... the sequence of constraint comparators must be an alternation of greater and lesser comparators:
        //   * "<" and "<=" must be followed by one of ">", ">=" (or no constraint).
        //   * ">" and ">=" must be followed by one of "<", "<=" (or no constraint).
        constraintIter = new PairwiseIterator<>(tmpConstraints);
        while (constraintIter.hasNext()) {
            final Pair<Constraint, Constraint> constraintPair = constraintIter.next();
            final Constraint currConstraint = constraintPair.getLeft();
            final Constraint nextConstraint = constraintPair.getRight();

            if (Set.of(Comparator.LESS_THAN, Comparator.LESS_THAN_OR_EQUAL).contains(currConstraint.comparator())
                    && !Set.of(Comparator.GREATER_THAN, Comparator.GREATER_THAN_OR_EQUAL).contains(nextConstraint.comparator())) {
                throw new VersException("A < or <= comparator must only be followed by a > or >= comparator, but got: %s"
                        .formatted(nextConstraint.comparator().operator()));
            }
            if (Set.of(Comparator.GREATER_THAN, Comparator.GREATER_THAN_OR_EQUAL).contains(currConstraint.comparator())
                    && !Set.of(Comparator.LESS_THAN, Comparator.LESS_THAN_OR_EQUAL).contains(nextConstraint.comparator())) {
                throw new VersException("A > or >= comparator must only be followed by a < or <= comparator, but got: %s"
                        .formatted(nextConstraint.comparator().operator()));
            }
        }

        return this;
    }

    @Override
    public String toString() {
        final String constraintsStr = constraints.stream()
                .map(Constraint::toString)
                .collect(Collectors.joining("|"));
        return "vers:%s/%s".formatted(versioningScheme, constraintsStr);
    }


}
