package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.PackageURL;

import java.util.UUID;

public record ComponentProjection(UUID componentUuid, String purlCoordinates, Boolean internal, PackageURL purl) {
}