package org.dependencytrack.event.kafka.componentmeta;

public record ComponentProjection(String purlCoordinates, Boolean internal, String purl) {
}
