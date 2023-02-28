package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import java.util.List;
import java.util.UUID;


public class ProjectMetricsProcessor implements Processor<String, ProjectMetrics, Void, Void> {
    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsProcessor.class);

    @Override
    public void process(Record<String, ProjectMetrics> record) {
        UUID uuid = UUID.fromString(record.key());
        try (final QueryManager qm = new QueryManager()) {

            final PersistenceManager pm = qm.getPersistenceManager();
            qm.runInTransaction(() -> {
                LOGGER.debug("Metrics of project " + uuid + " changed");
                pm.makePersistent(record.value());

            });
        }
        LOGGER.info("Completed metrics update for project " + uuid);

    }
}
