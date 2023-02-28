package org.dependencytrack.event.kafka.processor;

import alpine.common.logging.Logger;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.metrics.Counters;

import javax.jdo.PersistenceManager;


public class PortfolioMetricsProcessor implements Processor<String, PortfolioMetrics, Void, Void> {

    private static final Logger LOGGER = Logger.getLogger(PortfolioMetricsProcessor.class);

    @Override
    public void process(Record<String, PortfolioMetrics> record) {
        Counters counters = new Counters();
        try (final QueryManager qm = new QueryManager()) {
            PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
            if (metrics != null) {
                counters.setCritical(metrics.getCritical());
                counters.setHigh(metrics.getHigh());
                counters.setMedium(metrics.getMedium());
                counters.setLow(metrics.getLow());
                counters.setUnassigned(metrics.getUnassigned());
                counters.setInheritedRiskScore(metrics.getInheritedRiskScore());
                counters.setComponents(metrics.getComponents());
                counters.setVulnerableComponents(metrics.getVulnerableComponents());
                counters.setProjects(metrics.getProjects());
                counters.setVulnerableProjects(metrics.getVulnerableProjects());
                counters.setVulnerabilities(metrics.getVulnerabilities());
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
            final PersistenceManager pm = qm.getPersistenceManager();
            qm.runInTransaction(() -> {
                if (!counters.hasChanged(record.value())) {
                    LOGGER.debug("Portfolio metrics did not change");
                    record.value().setLastOccurrence(counters.getMeasuredAt());
                } else {
                    LOGGER.debug("Portfolio metrics changed");
                    pm.makePersistent(record.value());
                }
            });
            LOGGER.info("Completed metrics update for portfolio -- maybe add number of projects in this");
        }

    }
}
