package org.dependencytrack.policy.cel.persistence;

public record FieldMapping(String javaFieldName, String protoFieldName, String sqlColumnName) {
}
