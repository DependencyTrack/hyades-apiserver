package org.dependencytrack.policy.cel.mapping;

public record FieldMapping(String javaFieldName, String protoFieldName, String sqlColumnName) {
}
