package org.dependencytrack.event;

import alpine.event.framework.Event;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;

import java.util.Optional;
import java.util.UUID;

public record ComponentIntegrityCheckEvent(String purl, Boolean internal, String md5, String sha1,
                                           String sha256, UUID uuid, long componentId, String purlCoordinates) implements Event {
    public ComponentIntegrityCheckEvent(final Component component) {
        this(Optional.ofNullable(component.getPurl()).map(PackageURL::canonicalize).orElse(null), component.isInternal(), component.getMd5(),
                component.getSha1(), component.getSha256(), component.getUuid(), component.getId(), Optional.ofNullable(component.getPurlCoordinates()).map(PackageURL::canonicalize).orElse(null));
    }
    
}
