package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.persistence.QueryManager;

import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;

public class NistMirrorTask implements LoggableSubscriber {

    private static final Logger LOGGER = Logger.getLogger(NistMirrorTask.class);

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof NistMirrorEvent) {
            try (final QueryManager qm = new QueryManager()) {
                final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(), VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName());
                final boolean isEnabled = enabled != null && Boolean.valueOf(enabled.getPropertyValue());
                if (!isEnabled) {
                    return;
                }

                final long start = System.currentTimeMillis();
                LOGGER.info("Starting NIST mirroring task");
                new KafkaEventDispatcher().dispatchBlocking(new NistMirrorEvent());
                final long end = System.currentTimeMillis();
                LOGGER.info("NIST mirroring complete. Time spent (total): " + (end - start) + "ms");
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while triggering NIST mirroring", ex);
            }
        }
    }
}