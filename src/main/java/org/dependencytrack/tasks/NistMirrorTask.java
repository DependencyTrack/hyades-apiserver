package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;

public class NistMirrorTask implements LoggableSubscriber {

    private final boolean isEnabled;

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);

    public NistMirrorTask() {
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(), VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName());
            this.isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
         }
    }

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NistMirrorEvent && this.isEnabled) {
            final long start = System.currentTimeMillis();
            LOGGER.info("Starting NIST mirroring task");
            new KafkaEventDispatcher().dispatchBlocking(new NistMirrorEvent());
            final long end = System.currentTimeMillis();
            LOGGER.info("NIST mirroring complete. Time spent (total): " + (end - start) + "ms");
            Event.dispatch(new EpssMirrorEvent());
        }
    }
}
