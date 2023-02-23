package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;


public class PortfolioMetricsProcessor implements Processor<String, PortfolioMetrics, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(PortfolioMetricsProcessor.class);

    @Override
    public void process(Record<String, PortfolioMetrics> record) {
        try (final QueryManager qm = new QueryManager()) {
            final PersistenceManager pm = qm.getPersistenceManager();
            qm.runInTransaction(() -> {
                LOGGER.debug("Portfolio metrics changed");
                pm.makePersistent(record.value());
            });
            LOGGER.info("Completed metrics update for portfolio " + record.key());
        }

    }
}
