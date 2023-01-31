package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.Project;

import java.util.Objects;
import java.util.UUID;

/**
 * An {@link Event} used to trigger vulnerability analysis for all components within a given {@link Project}.
 */
public record ProjectRepositoryMetaAnalysisEvent(UUID projectUuid) implements Event {

    public ProjectRepositoryMetaAnalysisEvent(final UUID projectUuid) {
        this.projectUuid = Objects.requireNonNull(projectUuid, "Project UUID must not be null");
    }

}
