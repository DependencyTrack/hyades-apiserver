/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.notification;

import alpine.event.framework.LoggableUncaughtExceptionHandler;
import alpine.notification.NotificationLevel;
import com.google.protobuf.DebugFormat;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.dependencytrack.model.NotificationRule;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.publisher.PublishContext;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.Group;
import org.dependencytrack.proto.notification.v1.Level;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Scope;
import org.dependencytrack.proto.notification.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ScheduleWorkflowRunOptions;
import org.dependencytrack.workflow.payload.proto.v1alpha1.PublishNotificationWorkflowArgs;
import org.postgresql.PGConnection;
import org.postgresql.replication.LogSequenceNumber;
import org.postgresql.replication.PGReplicationStream;
import org.postgresql.util.PSQLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jdo.Query;
import javax.sql.DataSource;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.workflow.WorkflowEngineInitializer.workflowEngine;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;

public class NotificationRouter implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationRouter.class);
    private static final String PUBLICATION_NAME = "notification";
    private static final String REPLICATION_SLOT_NAME = "notification";

    private final DataSource dataSource;
    private ExecutorService executor;
    private volatile boolean stopping = false;

    public NotificationRouter(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    void start() {
        try (final Connection connection = dataSource.getConnection()) {
            ensurePublication(connection);
            ensureReplicationSlot(connection);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        stopping = false;
        executor = Executors.newSingleThreadExecutor(
                new BasicThreadFactory.Builder()
                        .namingPattern("NotificationRouter-%d")
                        .uncaughtExceptionHandler(new LoggableUncaughtExceptionHandler())
                        .build());
        executor.execute(() -> {
            try (final Connection connection = dataSource.getConnection();
                 final PGReplicationStream replicationStream = startReplicationStream(connection)) {
                while (!stopping) {
                    final ByteBuffer messageBuffer = replicationStream.readPending();
                    if (messageBuffer == null) {
                        TimeUnit.MILLISECONDS.sleep(1000);
                        continue;
                    }

                    // TODO: Consume a batch, route them, then "commit"?
                    //  Doing this one-by-one could prove a tad inefficient.
                    // TODO: On exception, sleep and rewind to last acked LSN.
                    final LogicalDecodingMessage decodedMessage = maybeDecode(messageBuffer);
                    if (decodedMessage != null) {
                        process(decodedMessage);
                    }

                    replicationStream.setAppliedLSN(replicationStream.getLastReceiveLSN());
                    replicationStream.setFlushedLSN(replicationStream.getLastReceiveLSN());
                }

                replicationStream.forceUpdateStatus();
            } catch (final SQLException | InterruptedException e) {
                // TODO: When another instance is already consuming from this slot,
                //  we get: `replication slot "notification" is active for PID XX`.
                //  Add a retry for that case, so another instance can resume the slot
                //  when the current consumer is stopped.
                LOGGER.error("Unable to start replication stream", e);
            }
        });
    }

    @Override
    public void close() {
        stopping = true;
        if (executor != null) {
            executor.close();
        }
    }

    private void process(final LogicalDecodingMessage message) {
        if (!"notification".equals(message.prefix())) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Skipping message with prefix {}", message.prefix());
            }

            return;
        }

        final Notification notification;
        try {
            notification = Notification.parseFrom(message.content());
        } catch (InvalidProtocolBufferException e) {
            LOGGER.warn("Failed to parse notification", e);
            return;
        }

        LOGGER.debug("Received notification: [{}]", DebugFormat.singleLine().lazyToString(notification));

        // TODO: Evaluate notification rules.

        final List<NotificationRule> matchedRules;
        try {
            final var publishContext = PublishContext.fromNotification(notification);
            matchedRules = resolveRules(publishContext, notification);
        } catch (IOException e) {
            throw new IllegalStateException("Failed resolve rules", e);
        }

        if (matchedRules.isEmpty()) {
            LOGGER.debug("No matching rules found");
            return;
        }

        // Depending on the type of notification, the notification content can be arbitrarily large.
        // We're better off using file storage for it, rather than submitting it as workflow argument.
        final FileMetadata notificationFileMetadata;
        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            final String fileName = "notifications/%d_%s.proto".formatted(Instant.now().toEpochMilli(), message.lsn().asLong());
            final String mediaType = "application/x-protobuf; type=" + notification.getDescriptorForType().getFullName();
            notificationFileMetadata = fileStorage.store(fileName, mediaType, notification.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to store notification", e);
        }

        // TODO: To enforce ordering (e.g. to ensure that all notifications for a project
        //  are delivered in order), we can build a concurrencyGroupId based on notification
        //  contents. Decide whether we want that, as it does introduce a bit of overhead.
        workflowEngine().scheduleWorkflowRun(
                new ScheduleWorkflowRunOptions("publish-notification", 1)
                        .withArgument(
                                PublishNotificationWorkflowArgs.newBuilder()
                                        .setNotificationFileMetadata(notificationFileMetadata)
                                        .addAllNotificationRuleNames(
                                                matchedRules.stream()
                                                        .map(NotificationRule::getName)
                                                        .toList())
                                        .build(),
                                protoConverter(PublishNotificationWorkflowArgs.class)));
    }

    private LogicalDecodingMessage maybeDecode(final ByteBuffer messageBuffer) {
        final var messageType = (char) messageBuffer.get();
        if (messageType == 'M') {
            return LogicalDecodingMessage.parse(messageBuffer);
        }

        if (messageType != /* BEGIN */ 'B' && messageType != /* COMMIT */ 'C') {
            LOGGER.warn("Unexpected message type: {}", messageType);
        } else if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Skipping message of type {}", messageType);
        }

        return null;
    }

    private record LogicalDecodingMessage(
            boolean isTransactional,
            LogSequenceNumber lsn,
            String prefix,
            byte[] content) {

        // https://github.com/debezium/debezium/blob/6246808308200ae9877f25f3a04e378578def98c/debezium-connector-postgres/src/main/java/io/debezium/connector/postgresql/connection/pgoutput/PgOutputMessageDecoder.java#L599
        private static LogicalDecodingMessage parse(final ByteBuffer buffer) {
            final boolean transactional = buffer.get() == 1;
            final LogSequenceNumber lsn = LogSequenceNumber.valueOf(buffer.getLong());
            final String prefix = getString(buffer);
            final int contentLength = buffer.getInt();
            final byte[] content = new byte[contentLength];
            buffer.get(content);

            return new LogicalDecodingMessage(transactional, lsn, prefix, content);
        }

        private static String getString(final ByteBuffer buffer) {
            final var stringBuilder = new StringBuilder();

            byte b;
            while ((b = buffer.get()) != 0) {
                stringBuilder.append((char) b);
            }

            return stringBuilder.toString();
        }

    }

    private void ensurePublication(final Connection connection) throws SQLException {
        try (final Statement statement = connection.createStatement()) {
            statement.execute("CREATE PUBLICATION " + PUBLICATION_NAME);
        } catch (PSQLException e) {
            // TODO: Is there an error code for this?
            if (!e.getMessage().contains("already exists")) {
                throw e;
            }
        }
    }

    private void ensureReplicationSlot(final Connection connection) throws SQLException {
        try {
            connection.unwrap(PGConnection.class).getReplicationAPI()
                    .createReplicationSlot()
                    .logical()
                    .withSlotName(REPLICATION_SLOT_NAME)
                    .withOutputPlugin("pgoutput")
                    .make();
        } catch (PSQLException e) {
            // TODO: Is there an error code for this?
            if (!e.getMessage().contains("already exists")) {
                throw e;
            }
        }
    }

    private PGReplicationStream startReplicationStream(final Connection connection) throws SQLException {
        return connection.unwrap(PGConnection.class).getReplicationAPI()
                .replicationStream()
                .logical()
                // https://www.postgresql.org/docs/current/protocol-logical-replication.html#PROTOCOL-LOGICAL-REPLICATION-PARAMS
                .withSlotOption("proto_version", "2")
                .withSlotOption("publication_names", PUBLICATION_NAME)
                .withSlotOption("messages", "true")
                .withSlotName(REPLICATION_SLOT_NAME)
                .withStatusInterval(5, TimeUnit.SECONDS) // TODO: What's a reasonable value?
                .start();
    }

    // ---

    List<NotificationRule> resolveRules(
            final PublishContext ctx,
            final Notification notification) throws InvalidProtocolBufferException {
        // The notification rules to process for this specific notification
        final List<NotificationRule> rules = new ArrayList<>();

        if (notification == null) {
            return rules;
        }

        final List<NotificationRule> result = getEnabledRulesByScopeAndLevel(notification.getScope(), notification.getLevel());
        LOGGER.debug("Matched %d notification rules (%s)".formatted(result.size(), ctx));
        if (notification.getScope() == SCOPE_PORTFOLIO
            && notification.getSubject().is(NewVulnerabilitySubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(NewVulnerabilitySubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(NewVulnerableDependencySubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(NewVulnerableDependencySubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(BomConsumedOrProcessedSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(BomConsumedOrProcessedSubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(BomProcessingFailedSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(BomProcessingFailedSubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(BomValidationFailedSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(BomValidationFailedSubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(VexConsumedOrProcessedSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(VexConsumedOrProcessedSubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(PolicyViolationSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(PolicyViolationSubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(VulnerabilityAnalysisDecisionChangeSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(VulnerabilityAnalysisDecisionChangeSubject.class).getProject());
        } else if (notification.getScope() == SCOPE_PORTFOLIO
                   && notification.getSubject().is(PolicyViolationAnalysisDecisionChangeSubject.class)) {
            limitToProject(ctx, rules, result, notification, notification.getSubject().unpack(PolicyViolationAnalysisDecisionChangeSubject.class).getProject());
        } else {
            for (final NotificationRule rule : result) {
                if (rule.getNotifyOn().contains(convert(notification.getGroup()))) {
                    rules.add(rule);
                }
            }
        }
        return rules;
    }

    private List<NotificationRule> getEnabledRulesByScopeAndLevel(final Scope scope, final Level level) {
        final var queryFilterParts = new ArrayList<>(List.of("enabled", "scope == :scope"));
        final var queryParams = new HashMap<>(Map.of("scope", convert(scope)));

        switch (level) {
            case LEVEL_INFORMATIONAL -> queryFilterParts.add("notificationLevel == 'INFORMATIONAL'");
            case LEVEL_WARNING -> queryFilterParts.add("""
                    (notificationLevel == 'WARNING' \
                    || notificationLevel == 'INFORMATIONAL')""");
            case LEVEL_ERROR -> queryFilterParts.add("""
                    (notificationLevel == 'ERROR' \
                    || notificationLevel == 'WARNING' \
                    || notificationLevel == 'INFORMATIONAL')""");
            default -> throw new IllegalArgumentException("Unexpected level: " + level);
        }

        try (final var qm = new QueryManager()) {
            final Query<NotificationRule> query = qm.getPersistenceManager().newQuery(NotificationRule.class);
            query.setFilter(String.join(" && ", queryFilterParts));
            query.setNamedParameters(queryParams);

            return List.copyOf(query.executeList());
        }
    }

    /**
     * if the rule specified one or more projects as targets, reduce the execution
     * of the notification down to those projects that the rule matches and which
     * also match projects affected by the vulnerability.
     */
    private void limitToProject(
            final PublishContext ctx,
            final List<NotificationRule> applicableRules,
            final List<NotificationRule> rules,
            final Notification notification,
            final org.dependencytrack.proto.notification.v1.Project limitToProject) {
        for (final NotificationRule rule : rules) {
            final PublishContext ruleCtx = ctx.withRule(rule);
            if (!rule.getNotifyOn().contains(convert(notification.getGroup()))) {
                continue;
            }

            final boolean isLimitedToProjects = rule.getProjects() != null && !rule.getProjects().isEmpty();
            final boolean isLimitedToTags = rule.getTags() != null && !rule.getTags().isEmpty();
            if (!isLimitedToProjects && !isLimitedToTags) {
                LOGGER.debug("Rule is not limited to projects or tags; Rule is applicable (%s)".formatted(ruleCtx));
                applicableRules.add(rule);
                continue;
            }

            if (isLimitedToTags) {
                final Predicate<Project> tagMatchPredicate = project ->
                        project.getTagsList() != null
                        && rule.getTags().stream()
                                .map(Tag::getName)
                                .anyMatch(project.getTagsList()::contains);

                if (tagMatchPredicate.test(limitToProject)) {
                    LOGGER.debug("""
                            Project %s is tagged with any of the "limit to" tags; \
                            Rule is applicable (%s)""".formatted(limitToProject.getUuid(), ruleCtx));
                    applicableRules.add(rule);
                    continue;
                }
            } else {
                LOGGER.debug("Rule is not limited to tags (%s)".formatted(ruleCtx));
            }

            if (isLimitedToProjects) {
                var matched = false;
                for (final org.dependencytrack.model.Project project : rule.getProjects()) {
                    if (project.getUuid().toString().equals(limitToProject.getUuid())) {
                        LOGGER.debug("Project %s is part of the \"limit to\" list of the rule; Rule is applicable (%s)"
                                .formatted(limitToProject.getUuid(), ruleCtx));
                        matched = true;
                        break;
                    } else if (rule.isNotifyChildren()) {
                        final boolean isChildOfLimitToProject = checkIfChildrenAreAffected(project, limitToProject.getUuid());
                        if (isChildOfLimitToProject) {
                            LOGGER.debug("Project %s is child of \"limit to\" project %s; Rule is applicable (%s)"
                                    .formatted(limitToProject.getUuid(), project.getUuid(), ruleCtx));
                            matched = true;
                            break;
                        } else {
                            LOGGER.debug("Project %s is not a child of \"limit to\" project %s (%s)"
                                    .formatted(limitToProject.getUuid(), project.getUuid(), ruleCtx));
                        }
                    }
                }
                if (matched) {
                    applicableRules.add(rule);
                } else {
                    LOGGER.debug("Project %s is not part of the \"limit to\" list of the rule; Rule is not applicable (%s)"
                            .formatted(limitToProject.getUuid(), ruleCtx));
                }
            } else {
                LOGGER.debug("Rule is not limited to projects (%s)".formatted(ruleCtx));
            }
        }
        LOGGER.debug("Applicable rules: %s (%s)"
                .formatted(applicableRules.stream().map(NotificationRule::getName).collect(Collectors.joining(", ")), ctx));
    }

    private boolean checkIfChildrenAreAffected(org.dependencytrack.model.Project parent, String uuid) {
        boolean isChild = false;
        if (parent.getChildren() == null || parent.getChildren().isEmpty()) {
            return false;
        }
        for (org.dependencytrack.model.Project child : parent.getChildren()) {
            if ((child.getUuid().toString().equals(uuid) && child.isActive()) || isChild) {
                return true;
            }
            isChild = checkIfChildrenAreAffected(child, uuid);
        }
        return isChild;
    }

    private static NotificationLevel convert(final Level level) {
        if (level == null) {
            throw new IllegalArgumentException("level must not be null");
        }

        return switch (level) {
            case LEVEL_ERROR -> NotificationLevel.ERROR;
            case LEVEL_WARNING -> NotificationLevel.WARNING;
            case LEVEL_INFORMATIONAL -> NotificationLevel.INFORMATIONAL;
            default -> throw new IllegalArgumentException("Unknown level: " + level);
        };
    }

    private static NotificationScope convert(final Scope scope) {
        if (scope == null) {
            throw new IllegalArgumentException("scope must not be null");
        }

        return switch (scope) {
            case SCOPE_PORTFOLIO -> NotificationScope.PORTFOLIO;
            case SCOPE_SYSTEM -> NotificationScope.SYSTEM;
            default -> throw new IllegalArgumentException("Unknown scope: " + scope);
        };
    }

    private static NotificationGroup convert(final Group group) {
        if (group == null) {
            throw new IllegalArgumentException("group must not be null");
        }

        return switch (group) {
            case GROUP_CONFIGURATION -> NotificationGroup.CONFIGURATION;
            case GROUP_DATASOURCE_MIRRORING -> NotificationGroup.DATASOURCE_MIRRORING;
            case GROUP_REPOSITORY -> NotificationGroup.REPOSITORY;
            case GROUP_INTEGRATION -> NotificationGroup.INTEGRATION;
            case GROUP_FILE_SYSTEM -> NotificationGroup.FILE_SYSTEM;
            case GROUP_ANALYZER -> NotificationGroup.ANALYZER;
            case GROUP_NEW_VULNERABILITY -> NotificationGroup.NEW_VULNERABILITY;
            case GROUP_NEW_VULNERABLE_DEPENDENCY -> NotificationGroup.NEW_VULNERABLE_DEPENDENCY;
            case GROUP_PROJECT_AUDIT_CHANGE -> NotificationGroup.PROJECT_AUDIT_CHANGE;
            case GROUP_BOM_CONSUMED -> NotificationGroup.BOM_CONSUMED;
            case GROUP_BOM_PROCESSED -> NotificationGroup.BOM_PROCESSED;
            case GROUP_BOM_PROCESSING_FAILED -> NotificationGroup.BOM_PROCESSING_FAILED;
            case GROUP_BOM_VALIDATION_FAILED -> NotificationGroup.BOM_VALIDATION_FAILED;
            case GROUP_VEX_CONSUMED -> NotificationGroup.VEX_CONSUMED;
            case GROUP_VEX_PROCESSED -> NotificationGroup.VEX_PROCESSED;
            case GROUP_POLICY_VIOLATION -> NotificationGroup.POLICY_VIOLATION;
            case GROUP_PROJECT_CREATED -> NotificationGroup.PROJECT_CREATED;
            case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> NotificationGroup.PROJECT_VULN_ANALYSIS_COMPLETE;
            case GROUP_USER_CREATED -> NotificationGroup.USER_CREATED;
            case GROUP_USER_DELETED -> NotificationGroup.USER_DELETED;
            default -> throw new IllegalArgumentException("Unknown group: " + group);
        };
    }

}
