package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Project;

import java.util.Objects;
import java.util.UUID;

/**
 * Defines an {@link Event} used to inform about the successful computation of component metrics.
 *
 * @param componentUuid {@link UUID} of the {@link Component}
 * @param projectUuid   {@link UUID} of the {@link Project} the {@link Component} belongs to
 * @param metrics       The computed {@link DependencyMetrics}, may be {@code null} to signal the deletion of a {@link Component}
 */
public record ComponentMetricsEvent(UUID componentUuid, UUID projectUuid, DependencyMetrics metrics) implements Event {

    public ComponentMetricsEvent(final UUID componentUuid, final UUID projectUuid, final DependencyMetrics metrics) {
        this.componentUuid = Objects.requireNonNull(componentUuid);
        this.projectUuid = Objects.requireNonNull(projectUuid);
        this.metrics = metrics;
    }

}
