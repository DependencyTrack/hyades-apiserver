package org.dependencytrack.event.kafka.processor;

import alpine.Config;
import alpine.common.logging.Logger;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.kafka.KafkaEvent;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.event.kafka.processor.api.BatchRecordProcessor;
import org.dependencytrack.event.kafka.processor.exception.RecordProcessingException;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.jdbi;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;

/**
 * A {@link BatchRecordProcessor} responsible for dispatching {@link NotificationGroup#BOM_PROCESSED} notifications
 * upon detection of a completed {@link VulnerabilityScan}.
 * <p>
 * The completion detection is based on {@link NotificationGroup#PROJECT_VULN_ANALYSIS_COMPLETE} notifications.
 * This processor does nothing unless {@link ConfigKey#TMP_DELAY_BOM_PROCESSED_NOTIFICATION} is enabled.
 */
public class DelayedBomProcessedNotificationProcessor implements BatchRecordProcessor<String, Notification> {

    public static final String PROCESSOR_NAME = "delayed.bom.processed.notification";

    private static final Logger LOGGER = Logger.getLogger(DelayedBomProcessedNotificationProcessor.class);

    private final Config config;
    private final KafkaEventDispatcher eventDispatcher;

    public DelayedBomProcessedNotificationProcessor() {
        this(Config.getInstance(), new KafkaEventDispatcher());
    }

    DelayedBomProcessedNotificationProcessor(final Config config, final KafkaEventDispatcher eventDispatcher) {
        this.config = config;
        this.eventDispatcher = eventDispatcher;
    }

    @Override
    public void process(final List<ConsumerRecord<String, Notification>> records) throws RecordProcessingException {
        if (!config.getPropertyAsBoolean(ConfigKey.TMP_DELAY_BOM_PROCESSED_NOTIFICATION)) {
            return;
        }

        final Set<String> tokens = extractTokens(records);
        if (tokens.isEmpty()) {
            LOGGER.warn("No token could be extracted from any of the %d records in this batch"
                    .formatted(records.size()));
            return;
        }

        final List<BomConsumedOrProcessedSubject> subjects;
        try (final var qm = new QueryManager()) {
            subjects = jdbi(qm).withExtension(NotificationSubjectDao.class,
                    dao -> dao.getForDelayedBomProcessed(tokens));
        }

        dispatchNotifications(subjects);
    }

    private static Set<String> extractTokens(final List<ConsumerRecord<String, Notification>> records) {
        final var tokens = new HashSet<String>();
        for (final ConsumerRecord<String, Notification> record : records) {
            final Notification notification = record.value();
            if (!notification.hasSubject() || !notification.getSubject().is(ProjectVulnAnalysisCompleteSubject.class)) {
                continue;
            }

            final ProjectVulnAnalysisCompleteSubject subject;
            try {
                subject = notification.getSubject().unpack(ProjectVulnAnalysisCompleteSubject.class);
            } catch (InvalidProtocolBufferException e) {
                LOGGER.warn("Failed to unpack notification subject from %s; Skipping".formatted(record), e);
                continue;
            }

            tokens.add(subject.getToken());
        }

        return tokens;
    }

    private void dispatchNotifications(final List<BomConsumedOrProcessedSubject> subjects) {
        final Timestamp timestamp = Timestamps.now();
        final var events = new ArrayList<KafkaEvent<String, Notification>>(subjects.size());
        for (final BomConsumedOrProcessedSubject subject : subjects) {
            final var event = new KafkaEvent<>(KafkaTopics.NOTIFICATION_BOM,
                    subject.getProject().getUuid(), Notification.newBuilder()
                    .setScope(SCOPE_PORTFOLIO)
                    .setGroup(GROUP_BOM_PROCESSED)
                    .setLevel(LEVEL_INFORMATIONAL)
                    .setTimestamp(timestamp)
                    .setTitle(NotificationConstants.Title.BOM_PROCESSED)
                    .setContent("A %s BOM was processed".formatted(subject.getBom().getFormat()))
                    .setSubject(Any.pack(subject))
                    .build());
            events.add(event);
        }

        eventDispatcher.dispatchAllBlocking(events);
    }

}
