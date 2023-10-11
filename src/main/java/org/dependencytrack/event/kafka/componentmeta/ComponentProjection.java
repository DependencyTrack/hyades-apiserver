package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.PackageURL;

public record ComponentProjection(String purlCoordinates, Boolean internal, PackageURL purl) {
}