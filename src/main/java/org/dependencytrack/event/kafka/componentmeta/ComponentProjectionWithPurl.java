package org.dependencytrack.event.kafka.componentmeta;

public record ComponentProjectionWithPurl(String purlCoordinates, Boolean internal, String purl) {
}