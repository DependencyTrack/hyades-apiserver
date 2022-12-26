package org.dependencytrack.event.kafka.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AnalyzerConfig(boolean SnykEnabled, boolean OSSEnabled, boolean internalAnalyzerEnabled) {
}
