package org.dependencytrack.event;

import alpine.event.framework.AbstractChainableEvent;
import alpine.event.framework.Event;
import org.dependencytrack.model.Component;

import java.util.UUID;

/**
 * Defines an {@link Event} used to trigger policy evaluations for {@link Component}s.
 *
 * @since 5.0.0
 */
public class ComponentPolicyEvaluationEvent extends AbstractChainableEvent {

    private final UUID uuid;

    public ComponentPolicyEvaluationEvent(final UUID uuid) {
        this.uuid = uuid;
    }

    public UUID getUuid() {
        return uuid;
    }

}
