package org.dependencytrack.event;

import alpine.common.logging.Logger;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockExtender;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.LockProvider;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.time.Duration;
import java.util.List;

import static org.dependencytrack.tasks.LockName.INTEGRITY_META_INITIALIZER_TASK_LOCK;
import static org.dependencytrack.util.LockProvider.isLockToBeExtended;

public class IntegrityMetaInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(IntegrityMetaInitializer.class);
    private final KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        try {
            LockProvider.executeWithLock(INTEGRITY_META_INITIALIZER_TASK_LOCK, (LockingTaskExecutor.Task) () -> process());
        } catch (Throwable e) {
            throw new RuntimeException("An unexpected error occurred while running Initializer for integrity meta", e);
        }
    }

    private void process() throws Exception {
        LOGGER.info("Initializing integrity meta component sync");
        LockConfiguration lockConfiguration = LockProvider.getLockConfigurationByLockName(INTEGRITY_META_INITIALIZER_TASK_LOCK);

        try (final var qm = new QueryManager()) {
            if (qm.getIntegrityMetaComponentCount() == 0) {

                // Sync purls from Component only if IntegrityMetaComponent is empty
                qm.synchronizeIntegrityMetaComponent();

                // dispatch ComponentRepositoryMetaAnalysisEvent for each purl
                final PersistenceManager pm = qm.getPersistenceManager();
                long offset = 0;
                long startTime = System.currentTimeMillis();
                List<String> purls = fetchNextPurlsPage(pm, offset);
                while (!purls.isEmpty()) {
                    long cumulativeProcessingTime = System.currentTimeMillis() - startTime;
                    if(isLockToBeExtended(cumulativeProcessingTime, INTEGRITY_META_INITIALIZER_TASK_LOCK)) {
                        LockExtender.extendActiveLock(Duration.ofMinutes(5).plus(lockConfiguration.getLockAtLeastFor()), lockConfiguration.getLockAtLeastFor());
                    }
                    dispatchPurls(pm, purls);

                    offset += purls.size();
                    purls = fetchNextPurlsPage(pm, offset);
                }
            } else {
                LOGGER.info("Skipping integrity meta initializer process as data already exists.");
            }
        }
    }

    private void dispatchPurls(PersistenceManager pm, List<String> purls) throws Exception {
        for (final var purl : purls) {
            try (final Query<Component> query = pm.newQuery(Component.class, "purl == :purl")) {
                query.setParameters(purl);
                query.setResult("DISTINCT purlCoordinates, internal");
                ComponentProjection componentProjection = query.executeResultUnique(ComponentProjection.class);
                kafkaEventDispatcher.dispatchAsync(new ComponentRepositoryMetaAnalysisEvent(componentProjection.purlCoordinates, componentProjection.internal));
            }
        }
    }

    private List<String> fetchNextPurlsPage(PersistenceManager pm, long offset) throws Exception {
        try (final Query<IntegrityMetaComponent> query = pm.newQuery(IntegrityMetaComponent.class)) {
            query.setRange(offset, offset + 5000);
            query.setResult("purl");
            return List.copyOf(query.executeResultList(String.class));
        }
    }

    public record ComponentProjection(String purlCoordinates, Boolean internal) {
    }
}
