package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.dependencytrack.event.kafka.processor.api.ProcessorManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class ProcessorInitializer implements ServletContextListener {

    private static final Logger LOGGER = Logger.getLogger(ProcessorInitializer.class);

    static final ProcessorManager PROCESSOR_MANAGER = new ProcessorManager();

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        LOGGER.info("Initializing processors");

        // TODO: Register processor here!

        PROCESSOR_MANAGER.startAll();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        LOGGER.info("Stopping processors");
        PROCESSOR_MANAGER.close();
    }

}