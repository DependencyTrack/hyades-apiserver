package org.dependencytrack.event.kafka.processor;

import alpine.Config;
import alpine.common.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class KafkaProcessorInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaProcessorInitializer.class);
    private static KafkaProcessorManager PROCESSOR_MANAGER;

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        PROCESSOR_MANAGER = new KafkaProcessorManager(Config.getInstance());
        LOGGER.info("Initializing Kafka processors (instance ID: %s)".formatted(PROCESSOR_MANAGER.getInstanceId()));
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        LOGGER.info("Stopping Kafka processors");
        if (PROCESSOR_MANAGER != null) {
            PROCESSOR_MANAGER.close();
            PROCESSOR_MANAGER = null;
        }
    }

    static KafkaProcessorManager processorManager() {
        return PROCESSOR_MANAGER;
    }

}
