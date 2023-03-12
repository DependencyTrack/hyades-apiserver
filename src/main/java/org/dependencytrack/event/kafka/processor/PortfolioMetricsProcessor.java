package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.persistence.QueryManager;

import java.util.Date;

public class PortfolioMetricsProcessor implements Processor<String, org.hyades.proto.metrics.v1.PortfolioMetrics, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(PortfolioMetricsProcessor.class);

    @Override
    public void process(final Record<String, org.hyades.proto.metrics.v1.PortfolioMetrics> record) {
        if (record.value() == null) {
            LOGGER.warn("Received tombstone event, but tombstones are currently not processed");
            return;
        }

        try (final QueryManager qm = new QueryManager()) {
            final PortfolioMetrics eventMetrics = mapToInternalModel(record.value());

            qm.runInTransaction(() -> {
                final PortfolioMetrics latestMetrics = qm.getMostRecentPortfolioMetrics();
                if (latestMetrics != null && !latestMetrics.hasChanged(eventMetrics)) {
                    LOGGER.debug("Portfolio metrics did not change");
                    latestMetrics.setLastOccurrence(new Date(record.timestamp()));
                } else {
                    LOGGER.debug("Portfolio metrics changed");
                    qm.getPersistenceManager().makePersistent(eventMetrics);
                }
            });
        }

        LOGGER.info("Completed metrics update for portfolio");
    }

    private static PortfolioMetrics mapToInternalModel(final org.hyades.proto.metrics.v1.PortfolioMetrics eventMetrics) {
        final var metrics = new PortfolioMetrics();
        metrics.setProjects(eventMetrics.getProjects());
        metrics.setVulnerableProjects(eventMetrics.getVulnerableProjects());
        metrics.setComponents(eventMetrics.getComponents());
        metrics.setVulnerableComponents(eventMetrics.getVulnerableComponents());
        metrics.setInheritedRiskScore(eventMetrics.getInheritedRiskScore());
        metrics.setVulnerabilities(eventMetrics.getVulnerabilities().getTotal());
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
