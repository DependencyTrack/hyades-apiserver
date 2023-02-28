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
            qm.getPersistenceManager().refreshAll();
            ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);

            //if project has existing metrics in the db, we need to match it with the metrics we have received.
            //if they are the same then existing entry is updated for timestamp, else new project metrics entry is created.
            //to compare we need to populate counters with existing metrics and then use hasChanged to check difference
            if(metrics!=null) {
                counters.setCritical(metrics.getCritical());
                counters.setHigh(metrics.getHigh());
                counters.setMedium(metrics.getMedium());
                counters.setLow(metrics.getLow());
                counters.setUnassigned(metrics.getUnassigned());
                counters.setInheritedRiskScore(metrics.getInheritedRiskScore());
                counters.setComponents(metrics.getComponents());
                counters.setVulnerableComponents(metrics.getVulnerableComponents());
                counters.setVulnerabilities((int) metrics.getVulnerabilities());
                counters.setSuppressions(metrics.getSuppressed());
                counters.setFindingsTotal(metrics.getFindingsTotal());
                counters.setFindingsAudited(metrics.getFindingsAudited());
                counters.setFindingsUnaudited(metrics.getFindingsUnaudited());
                counters.setPolicyViolationsFail(metrics.getPolicyViolationsFail());
                counters.setPolicyViolationsWarn(metrics.getPolicyViolationsWarn());
                counters.setPolicyViolationsInfo(metrics.getPolicyViolationsInfo());
                counters.setPolicyViolationsTotal(metrics.getPolicyViolationsTotal());
                counters.setPolicyViolationsAudited(metrics.getPolicyViolationsAudited());
                counters.setPolicyViolationsUnaudited(metrics.getPolicyViolationsUnaudited());
                counters.setPolicyViolationsSecurityTotal(metrics.getPolicyViolationsSecurityTotal());
                counters.setPolicyViolationsSecurityUnaudited(metrics.getPolicyViolationsSecurityUnaudited());
                counters.setPolicyViolationsSecurityAudited(metrics.getPolicyViolationsSecurityAudited());
                counters.setPolicyViolationsLicenseTotal(metrics.getPolicyViolationsLicenseTotal());
                counters.setPolicyViolationsLicenseAudited(metrics.getPolicyViolationsLicenseAudited());
                counters.setPolicyViolationsLicenseUnaudited(metrics.getPolicyViolationsLicenseUnaudited());
                counters.setPolicyViolationsOperationalTotal(metrics.getPolicyViolationsOperationalTotal());
                counters.setPolicyViolationsOperationalAudited(metrics.getPolicyViolationsOperationalAudited());
                counters.setPolicyViolationsOperationalUnaudited(metrics.getPolicyViolationsOperationalUnaudited());
            }
            qm.runInTransaction(() -> {
                if (metrics!=null && !counters.hasChanged(record.value())) {
                    LOGGER.debug("Metrics of project " + uuid + " did not change");
                    record.value().setLastOccurrence(counters.getMeasuredAt());
                } else {
                    LOGGER.debug("Metrics of project " + uuid + " changed");
                    record.value().setProject(project);
                    pm.makePersistent(record.value());
                }

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
