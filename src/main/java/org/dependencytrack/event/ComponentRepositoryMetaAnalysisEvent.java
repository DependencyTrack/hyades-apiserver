package org.dependencytrack.event;

import alpine.event.framework.Event;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * Defines an {@link Event} triggered when requesting a component to be analyzed for meta information.
 *
 * @param purlCoordinates The package URL coordinates of the {@link Component} to analyze
 * @param internal        Whether the {@link Component} is internal
 */
public record ComponentRepositoryMetaAnalysisEvent(String purlCoordinates, Boolean internal, String md5, String sha1,
                                                   String sha256, UUID uuid) implements Event {

    public ComponentRepositoryMetaAnalysisEvent(final Component component) {
        this(Optional.ofNullable(component.getPurlCoordinates()).map(PackageURL::canonicalize).orElse(null), component.isInternal(), component.getMd5(),
                component.getSha1(), component.getSha256(), component.getUuid());
    }

}
