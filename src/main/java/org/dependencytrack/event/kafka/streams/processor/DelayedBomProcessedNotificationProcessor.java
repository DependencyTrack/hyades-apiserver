package org.dependencytrack.event.kafka.streams.processor;

import alpine.common.logging.Logger;
import alpine.notification.NotificationLevel;
import org.apache.kafka.streams.processor.api.ContextualProcessor;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.Record;
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.notification.v1.Notification;

import javax.jdo.Query;
import java.util.UUID;

import static org.dependencytrack.parser.dependencytrack.NotificationModelConverter.convert;

/**
 * A {@link Processor} responsible for dispatching {@link NotificationGroup#BOM_PROCESSED} notifications
 * upon detection of a completed {@link VulnerabilityScan}.
 */
public class DelayedBomProcessedNotificationProcessor extends ContextualProcessor<String, VulnerabilityScan, String, Notification> {

    private static final Logger LOGGER = Logger.getLogger(DelayedBomProcessedNotificationProcessor.class);

    @Override
    public void process(final Record<String, VulnerabilityScan> record) {
        final VulnerabilityScan vulnScan = record.value();

        if (vulnScan.getStatus() != VulnerabilityScan.Status.COMPLETED
                && vulnScan.getStatus() != VulnerabilityScan.Status.FAILED) {
            LOGGER.warn("Received vulnerability scan with non-terminal status %s; Dropping (token=%s, project=%s)"
                    .formatted(vulnScan.getStatus(), vulnScan.getToken(), vulnScan.getTargetIdentifier()));
            return;
        }

        final Project project;
        try (final var qm = new QueryManager()) {
            if (!qm.hasWorkflowStepWithStatus(UUID.fromString(vulnScan.getToken()), WorkflowStep.BOM_PROCESSING, WorkflowStatus.COMPLETED)) {
                LOGGER.debug("Received completed vulnerability scan, but no %s step exists in this workflow; Dropping (token=%s, project=%s)"
                        .formatted(WorkflowStep.BOM_PROCESSING, vulnScan.getToken(), vulnScan.getTargetIdentifier()));
                return;
            }

            project = getProject(qm, vulnScan.getTargetIdentifier());
            if (project == null) {
                LOGGER.warn("Received completed vulnerability scan, but the target project does not exist; Dropping (token=%s, project=%s)"
                        .formatted(vulnScan.getToken(), vulnScan.getTargetIdentifier()));
                return;
            }
        }

        final var alpineNotification = new alpine.notification.Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.BOM_PROCESSED)
                .level(NotificationLevel.INFORMATIONAL)
                .title(NotificationConstants.Title.BOM_PROCESSED)
                // BOM format and spec version are hardcoded because we don't have this information at this point.
                // DT currently only accepts CycloneDX anyway.
                .content("A %s BOM was processed".formatted(Bom.Format.CYCLONEDX.getFormatShortName()))
                .subject(new BomConsumedOrProcessed(UUID.fromString(vulnScan.getToken()), project, /* bom */ "(Omitted)", Bom.Format.CYCLONEDX, "Unknown"));

        context().forward(record.withKey(project.getUuid().toString()).withValue(convert(alpineNotification)));
        LOGGER.info("Dispatched delayed %s notification (token=%s, project=%s)"
                .formatted(NotificationGroup.BOM_PROCESSED, vulnScan.getToken(), vulnScan.getTargetIdentifier()));
    }

    private static Project getProject(final QueryManager qm, final UUID uuid) {
        final Query<Project> projectQuery = qm.getPersistenceManager().newQuery(Project.class);
        projectQuery.setFilter("uuid == :uuid");
        projectQuery.setParameters(uuid);
        projectQuery.getFetchPlan().clearGroups(); // Ensure we're not loading too much bloat.
        projectQuery.getFetchPlan().setGroup(Project.FetchGroup.NOTIFICATION.name());
        try {
            return qm.getPersistenceManager().detachCopy(projectQuery.executeResultUnique(Project.class));
        } finally {
            projectQuery.closeAll();
        }
    }

}
