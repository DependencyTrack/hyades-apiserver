package org.dependencytrack.event;

import alpine.common.logging.Logger;
import org.dependencytrack.persistence.QueryManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class IntegrityMetaInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(IntegrityMetaInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing integrity meta component sync");
        try (final var qm = new QueryManager()) {
            // Sync purls from Component only if IntegrityMetaComponent is empty
            if (qm.getIntegrityMetaComponentCount() == 0) {
                qm.synchronizeIntegrityMetaComponent();
            } else {
                LOGGER.info("Skipping initial integrity meta component synchronizing as data already exists.");
            }
        }
    }
}
