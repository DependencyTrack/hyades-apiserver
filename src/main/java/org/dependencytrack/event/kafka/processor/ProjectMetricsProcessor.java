package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.persistence.QueryManager;

import java.util.Date;
import java.util.UUID;

public class ProjectMetricsProcessor implements Processor<String, org.hyades.proto.metrics.v1.ProjectMetrics, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(ProjectMetricsProcessor.class);

    @Override
    public void process(final Record<String, org.hyades.proto.metrics.v1.ProjectMetrics> record) {
        final UUID uuid = UUID.fromString(record.key());

        if (record.value() == null) {
            LOGGER.warn("Received tombstone event for project %s");
            return;
        }

        try (final QueryManager qm = new QueryManager()) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                LOGGER.warn("Received metrics for project %s, but it does not exist (anymore?)".formatted(uuid));
                return;
            }

            final ProjectMetrics eventMetrics = mapToInternalModel(record.value());

            qm.runInTransaction(() -> {
                final ProjectMetrics latestMetrics = qm.getMostRecentProjectMetrics(project);
                if (latestMetrics != null && !latestMetrics.hasChanged(eventMetrics)) {
                    LOGGER.debug("Metrics of project " + uuid + " did not change");
                    latestMetrics.setLastOccurrence(new Date(record.timestamp()));
                } else {
                    LOGGER.debug("Metrics of project " + uuid + " changed");
                    eventMetrics.setProject(project);
                    eventMetrics.setFirstOccurrence(new Date(record.timestamp()));
                    eventMetrics.setLastOccurrence(new Date(record.timestamp()));
                    qm.getPersistenceManager().makePersistent(eventMetrics);
                }
            });

            if (project.getLastInheritedRiskScore() == null ||
                    project.getLastInheritedRiskScore() != eventMetrics.getInheritedRiskScore()) {
                LOGGER.debug("Updating inherited risk score of project " + uuid);
                qm.runInTransaction(() -> project.setLastInheritedRiskScore(eventMetrics.getInheritedRiskScore()));
            }
        }

        LOGGER.info("Successfully processed metrics update for project " + uuid);
    }

    private static ProjectMetrics mapToInternalModel(final org.hyades.proto.metrics.v1.ProjectMetrics eventMetrics) {
        final var metrics = new ProjectMetrics();
        metrics.setComponents(eventMetrics.getComponents());
        metrics.setVulnerableComponents(eventMetrics.getVulnerableComponents());
        metrics.setVulnerabilities(eventMetrics.getVulnerabilities().getTotal());
        metrics.setInheritedRiskScore(eventMetrics.getInheritedRiskScore());
        metrics.setCritical(eventMetrics.getVulnerabilities().getCritical());
        metrics.setHigh(eventMetrics.getVulnerabilities().getHigh());
        metrics.setMedium(eventMetrics.getVulnerabilities().getMedium());
        metrics.setLow(eventMetrics.getVulnerabilities().getLow());
        metrics.setUnassigned(eventMetrics.getVulnerabilities().getUnassigned());
        metrics.setFindingsTotal(eventMetrics.getFindings().getTotal());
        metrics.setFindingsAudited(eventMetrics.getFindings().getAudited());
        metrics.setFindingsUnaudited(eventMetrics.getFindings().getUnaudited());
        metrics.setSuppressed(eventMetrics.getFindings().getSuppressed());
        metrics.setPolicyViolationsTotal(eventMetrics.getPolicyViolations().getTotal());
        metrics.setPolicyViolationsFail(eventMetrics.getPolicyViolations().getFail());
        metrics.setPolicyViolationsWarn(eventMetrics.getPolicyViolations().getWarn());
        metrics.setPolicyViolationsInfo(eventMetrics.getPolicyViolations().getInfo());
        metrics.setPolicyViolationsAudited(eventMetrics.getPolicyViolations().getAudited());
        metrics.setPolicyViolationsUnaudited(eventMetrics.getPolicyViolations().getUnaudited());
        metrics.setPolicyViolationsLicenseTotal(eventMetrics.getPolicyViolations().getLicenseTotal());
        metrics.setPolicyViolationsLicenseAudited(eventMetrics.getPolicyViolations().getLicenseAudited());
        metrics.setPolicyViolationsLicenseUnaudited(eventMetrics.getPolicyViolations().getLicenseUnaudited());
        metrics.setPolicyViolationsOperationalTotal(eventMetrics.getPolicyViolations().getOperationalTotal());
        metrics.setPolicyViolationsOperationalAudited(eventMetrics.getPolicyViolations().getOperationalAudited());
        metrics.setPolicyViolationsOperationalUnaudited(eventMetrics.getPolicyViolations().getOperationalUnaudited());
        metrics.setPolicyViolationsSecurityTotal(eventMetrics.getPolicyViolations().getSecurityTotal());
        metrics.setPolicyViolationsSecurityAudited(eventMetrics.getPolicyViolations().getSecurityAudited());
        metrics.setPolicyViolationsSecurityUnaudited(eventMetrics.getPolicyViolations().getSecurityUnaudited());
        return metrics;
    }

}
