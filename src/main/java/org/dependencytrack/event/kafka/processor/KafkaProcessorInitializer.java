package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class KafkaProcessorInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(KafkaProcessorInitializer.class);

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing Kafka processors");

        final var processorFactory = new KafkaProcessorFactory();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Stopping Kafka processors");
    }

}
