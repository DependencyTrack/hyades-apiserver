package org.dependencytrack.event.kafka.processor;

import alpine.Config;
import alpine.common.logging.Logger;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.processor.api.RecordProcessorManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class KafkaProcessorsInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaProcessorsInitializer.class);

    static final RecordProcessorManager PROCESSOR_MANAGER = new RecordProcessorManager();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka processors");

        PROCESSOR_MANAGER.registerProcessor(VulnerabilityMirrorProcessor.PROCESSOR_NAME,
                new VulnerabilityMirrorProcessor(), KafkaTopics.NEW_VULNERABILITY);
        PROCESSOR_MANAGER.registerProcessor(RepositoryMetaResultProcessor.PROCESSOR_NAME,
                new RepositoryMetaResultProcessor(), KafkaTopics.REPO_META_ANALYSIS_RESULT);
        PROCESSOR_MANAGER.registerBatchProcessor(ProcessedVulnerabilityScanResultProcessor.PROCESSOR_NAME,
                new ProcessedVulnerabilityScanResultProcessor(), KafkaTopics.VULN_ANALYSIS_RESULT_PROCESSED);
        if (Config.getInstance().getPropertyAsBoolean(ConfigKey.TMP_DELAY_BOM_PROCESSED_NOTIFICATION)) {
            PROCESSOR_MANAGER.registerBatchProcessor(DelayedBomProcessedNotificationProcessor.PROCESSOR_NAME,
                    new DelayedBomProcessedNotificationProcessor(), KafkaTopics.NOTIFICATION_PROJECT_VULN_ANALYSIS_COMPLETE);
        }

        PROCESSOR_MANAGER.startAll();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Stopping Kafka processors");
        PROCESSOR_MANAGER.close();
    }

}
