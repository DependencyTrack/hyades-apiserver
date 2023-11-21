package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;
import org.dependencytrack.proto.repometaanalysis.v1.FetchMeta;

import java.util.UUID;

/**
 * Defines an {@link Event} triggered when requesting a component to be analyzed for meta information.
 *
 * @param purlCoordinates The package URL coordinates of the {@link Component} to analyze
 * @param internal        Whether the {@link Component} is internal
 * @param fetchMeta       Whether component hash data or component meta data needs to be fetched from external api
 */
public record ComponentRepositoryMetaAnalysisEvent(UUID componentUuid, String purlCoordinates, Boolean internal,
                                                   FetchMeta fetchMeta) implements Event {

}
