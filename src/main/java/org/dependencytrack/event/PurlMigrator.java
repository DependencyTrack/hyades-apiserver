package org.dependencytrack.event;

import alpine.Config;
import alpine.common.logging.Logger;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.LockProvider;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import static org.dependencytrack.tasks.LockName.INTEGRITY_META_INITIALIZER_LOCK;

public class PurlMigrator implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(PurlMigrator.class);
    private final boolean integrityInitializerEnabled;

    public PurlMigrator() {
        this(Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_INITIALIZER_ENABLED));
    }

    PurlMigrator(final boolean integrityInitializerEnabled) {
        this.integrityInitializerEnabled = integrityInitializerEnabled;
    }


    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (integrityInitializerEnabled) {
            try {
                LockProvider.executeWithLock(INTEGRITY_META_INITIALIZER_LOCK, (LockingTaskExecutor.Task) () -> process());
            } catch (Throwable e) {
                throw new RuntimeException("An unexpected error occurred while running Initializer for integrity meta", e);
            }
        } else {
            LOGGER.info("Component integrity initializer is disabled.");
        }
    }

    private void process() {
        LOGGER.info("Initializing integrity meta component sync");
        try (final var qm = new QueryManager()) {
            qm.synchronizeIntegrityMetaComponent();
        }
    }
}
