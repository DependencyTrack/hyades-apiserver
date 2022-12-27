package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.event.kafka.dto.AnalyzerCompletionStatus;
import org.dependencytrack.event.kafka.dto.AnalyzerConfig;
import org.dependencytrack.event.kafka.dto.VulnerabilityResult;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.AnalyzerCompletionTracker;
import org.dependencytrack.util.NotificationUtil;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

public class ComponentAnalyzerConfigProcessor implements Processor<UUID, AnalyzerConfig, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(ComponentAnalyzerConfigProcessor.class);

    @Override
    public void process(final Record<UUID, AnalyzerConfig> record) {
        final UUID componentUuid = record.key();
        final AnalyzerConfig result = record.value();

        try (final var qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                LOGGER.warn("Component " + componentUuid + " does not exist");
                return;
            }
            LOGGER.info("Received Analyzer config ");
            LOGGER.info(" - Component: " + component);
            try {
                AnalyzerCompletionTracker.analyzerConfigMap.put(componentUuid, result);
            } finally {
                // Ensure that the last vulnerability analysis timestamp is always updated.
                // Alternatively, implement a retry mechanism.
                qm.runInTransaction(() -> component.setLastVulnerabilityAnalysis(new Date()));
            }
        }
    }
}
