package org.dependencytrack.event;

import alpine.event.framework.Event;
import org.dependencytrack.model.IntegrityMetaComponent;

import java.util.UUID;

public class IntegrityAnalysisEvent implements Event {

    private UUID uuid;

    private IntegrityMetaComponent integrityMetaComponent;

    public IntegrityAnalysisEvent(UUID uuid, IntegrityMetaComponent integrityMetaComponent) {
        this.uuid = uuid;
        this.integrityMetaComponent = integrityMetaComponent;
    }

    public UUID getUuid() {
        return uuid;
    }

    public IntegrityMetaComponent getIntegrityMetaComponent() {
        return integrityMetaComponent;
    }
}
