package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.IntegrityAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;

import java.util.UUID;

import static org.dependencytrack.event.kafka.componentmeta.IntegrityCheck.calculateIntegrityResult;

public class IntegrityAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(IntegrityAnalysisTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final IntegrityAnalysisEvent event) {
            if (!Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_CHECK_ENABLED)) {
                return;
            }
            LOGGER.debug("Performing integrity analysis for component: " + event.getUuid());
            if(event.getUuid() == null) {
                return;
            }
            try (final var qm = new QueryManager()) {
                UUID uuid = event.getUuid();
                IntegrityMetaComponent integrityMetaComponent = event.getIntegrityMetaComponent();
                Component component = qm.getObjectByUuid(Component.class, uuid);
                calculateIntegrityResult(integrityMetaComponent, component, qm);
            }
        }
    }
}
