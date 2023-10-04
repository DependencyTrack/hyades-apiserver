package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;
import org.hyades.proto.repometaanalysis.v1.FetchMeta;

/**
 * Defines an {@link Event} triggered when requesting a component to be analyzed for meta information.
 *
 * @param purlCoordinates    The package URL coordinates of the {@link Component} to analyze
 * @param internal           Whether the {@link Component} is internal
 * @param fetchIntegrityData Whether component hash information needs to be fetched from external api
 * @param fetchLatestVersion Whether to fetch latest version meta information for a component.
 */
public record ComponentRepositoryMetaAnalysisEvent(String purlCoordinates, Boolean internal,
                                                  FetchMeta fetchIntegrityData, FetchMeta fetchLatestVersion ) implements Event {

}
