package org.dependencytrack.event;

import alpine.Config;
import alpine.common.logging.Logger;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.LockProvider;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.dependencytrack.tasks.LockName.INTEGRITY_META_INITIALIZER_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.isLockToBeExtended;

public class IntegrityMetaInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(IntegrityMetaInitializer.class);
    private final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
    private final boolean integrityInitializerEnabled;

    public IntegrityMetaInitializer() {
        this(Config.getInstance().getPropertyAsBoolean(ConfigKey.INTEGRITY_INITIALIZER_ENABLED));
    }

    IntegrityMetaInitializer(final boolean integrityInitializerEnabled) {
        this.integrityInitializerEnabled = integrityInitializerEnabled;
    }


    @Override
    public void contextInitialized(final ServletContextEvent event) {
        if (integrityInitializerEnabled) {
            try {
                LockProvider.executeWithLock(INTEGRITY_META_INITIALIZER_TASK_LOCK, (LockingTaskExecutor.Task) () -> process());
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
            if (qm.getIntegrityMetaComponentCount() == 0) {
                // Sync purls from Component only if IntegrityMetaComponent is empty
                qm.synchronizeIntegrityMetaComponent();
            }
            // dispatch purls not processed yet
            batchProcessPurls(qm);
        }
    }

    private void batchProcessPurls(QueryManager qm) {
        LockConfiguration lockConfiguration = LockProvider.getLockConfigurationByLockName(INTEGRITY_META_INITIALIZER_TASK_LOCK);
        long offset = 0;
        long startTime = System.currentTimeMillis();
        List<String> purls = qm.fetchNextPurlsPage(offset);
        while (!purls.isEmpty()) {
            long cumulativeProcessingTime = System.currentTimeMillis() - startTime;
            if (isLockToBeExtended(cumulativeProcessingTime, INTEGRITY_META_INITIALIZER_TASK_LOCK)) {
                LockExtender.extendActiveLock(Duration.ofMinutes(5).plus(lockConfiguration.getLockAtLeastFor()), lockConfiguration.getLockAtLeastFor());
            }
            dispatchPurls(qm, purls);
            updateIntegrityMetaForPurls(qm, purls);
            offset += purls.size();
            purls = qm.fetchNextPurlsPage(offset);
        }
    }

    private void updateIntegrityMetaForPurls(QueryManager qm, List<String> purls) {
        List<IntegrityMetaComponent> purlRecords = new ArrayList<>();
        for (var purl : purls) {
            purlRecords.add(qm.getIntegrityMetaComponent(purl));
        }
        qm.batchUpdateIntegrityMetaComponent(purlRecords);
    }

    private void dispatchPurls(QueryManager qm, List<String> purls) {
        for (final var purl : purls) {
            ComponentProjection componentProjection = qm.getComponentByPurl(purl);
            kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates, componentProjection.internal, true, false));
        }
    }

    public record ComponentProjection(String purlCoordinates, Boolean internal) {
    }
}
