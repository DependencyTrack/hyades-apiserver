package org.dependencytrack.resources.v1.vo;

public record CelExpressionError(Integer line, Integer column, String message) {
}
