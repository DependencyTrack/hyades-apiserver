package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.metrics.Counters;

import javax.jdo.PersistenceManager;
import java.util.UUID;


public class ProjectMetricsProcessor implements Processor<String, ProjectMetrics, Void, Void> {
    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsProcessor.class);

    @Override
    public void process(Record<String, ProjectMetrics> record) {
        UUID uuid = UUID.fromString(record.key());
        Counters counters = new Counters();
        try (final QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, uuid);
            final PersistenceManager pm = qm.getPersistenceManager();
            qm.runInTransaction(() -> {
                LOGGER.debug("Metrics of project " + uuid + " changed");
                record.value().setProject(project);
                pm.makePersistent(record.value());
            });
            if (project.getLastInheritedRiskScore() == null ||
                    project.getLastInheritedRiskScore() != counters.getInheritedRiskScore()) {
                LOGGER.debug("Updating inherited risk score of project " + uuid);
                qm.runInTransaction(() -> project.setLastInheritedRiskScore(counters.getInheritedRiskScore()));
            }
        }
        LOGGER.info("Completed metrics update for project " + uuid);

    }
}
