package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;

import java.util.Objects;

/**
 * Defines an {@link Event} triggered when requesting a component to be analyzed for meta information.
 *
 * @param component The {@link Component} to analyze
 */
public record ComponentRepositoryMetaAnalysisEvent(Component component) implements Event {

    public ComponentRepositoryMetaAnalysisEvent(final Component component) {
        this.component = Objects.requireNonNull(component);
    }

}
