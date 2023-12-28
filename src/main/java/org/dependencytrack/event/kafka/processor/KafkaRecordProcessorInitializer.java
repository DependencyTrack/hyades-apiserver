package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.processor.api.RecordProcessorManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class KafkaRecordProcessorInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaRecordProcessorInitializer.class);

    private final RecordProcessorManager processorManager = new RecordProcessorManager();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka processors");

        processorManager.register(VulnerabilityMirrorProcessor.PROCESSOR_NAME,
                new VulnerabilityMirrorProcessor(), KafkaTopics.NEW_VULNERABILITY);
        processorManager.register(RepositoryMetaResultProcessor.PROCESSOR_NAME,
                new RepositoryMetaResultProcessor(), KafkaTopics.REPO_META_ANALYSIS_RESULT);
        processorManager.startAll();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Stopping Kafka processors");
        processorManager.close();
    }

}
