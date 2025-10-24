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

import com.google.protobuf.Any;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.Project;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * Dispatcher of notifications.
 *
 * @since 5.7.0
 */
public final class NotificationDispatcher implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationDispatcher.class);

    private final Consumer<List<NotificationPublishTask>> publisher;
    private final int batchSize;

    public NotificationDispatcher(
            final Consumer<List<NotificationPublishTask>> publisher,
            final int batchSize) {
        this.publisher = publisher;
        this.batchSize = batchSize;
    }

    @Override
    public void run() {
        // TODO: Make this run in a (scheduled?) loop.
        useJdbiTransaction(handle -> {
            // Acquire advisory lock to prevent concurrent dispatching from multiple instances.
            //
            // Ideally we want dispatches to happen in the order in which notifications were
            // emitted. Work-stealing polling with FOR UPDATE SKIP LOCKED would mess with ordering.
            //
            // The lack of concurrency is in part mitigated by processing notifications in batches.
            final boolean lockAcquired = tryAcquireAdvisoryLock(handle);
            if (!lockAcquired) {
                LOGGER.debug("Lock already acquired by another instance");
                return;
            }

            final Map<UUID, Notification> notificationById =
                    pollNotifications(handle).stream()
                            .collect(Collectors.toMap(
                                    notification -> UUID.fromString(notification.getId()),
                                    Function.identity()));

            LOGGER.info("Poll returned {} notifications", notificationById.size());
            if (notificationById.isEmpty()) {
                return;
            }

            final Map<UUID, List<NotificationRuleRecord>> rulesByNotificationId =
                    resolveRules(handle, notificationById.values());

            final var publishTasks = new ArrayList<NotificationPublishTask>();

            for (final Map.Entry<UUID, List<NotificationRuleRecord>> entry : rulesByNotificationId.entrySet()) {
                final Notification notification = notificationById.get(entry.getKey());
                final List<Long> applicableRuleIds = filterRules(notification, entry.getValue());

                for (final Long ruleId : applicableRuleIds) {
                    publishTasks.add(new NotificationPublishTask(ruleId, notification));
                }
            }

            // The publisher is expected to be atomic, i.e. it should accept all tasks
            // or none at all. Should committing the current database transaction fail,
            // the same notifications may be sent multiple times to the publisher.
            // This is an acceptable trade-off since we want at-least-once semantics.
            //
            // Duplicate notifications may be de-duped by the receiver using their ID.
            if (!publishTasks.isEmpty()) {
                LOGGER.debug("Producing {} publish tasks", publishTasks.size());
                publisher.accept(publishTasks);
            }
        });
    }

    private boolean tryAcquireAdvisoryLock(final Handle handle) {
        return handle.createQuery("""
                        -- TODO: Define proper lock ID.
                        SELECT pg_try_advisory_xact_lock(123)
                        """)
                .mapTo(boolean.class)
                .one();
    }

    private List<Notification> pollNotifications(final Handle jdbiHandle) {
        final Query query = jdbiHandle.createQuery("""
                WITH polled AS (
                  SELECT "ID"
                    FROM "NOTIFICATION"
                   ORDER BY "ID"
                   LIMIT :limit
                )
                DELETE
                  FROM "NOTIFICATION"
                 WHERE "ID" IN (SELECT "ID" FROM polled)
                RETURNING "PAYLOAD"
                """);

        return query
                .bind("limit", batchSize)
                .mapTo(byte[].class)
                .stream()
                .map(this::deserialize)
                .toList();
    }

    public record NotificationRuleRecord(
            int index,
            long id,
            String name,
            boolean isNotifyChildProjects,
            boolean isLimitedToProjects,
            boolean isLimitedToTags) {
    }

    private Map<UUID, List<NotificationRuleRecord>> resolveRules(
            final Handle jdbiHandle,
            final Collection<Notification> notifications) {
        final var subQueries = new ArrayList<String>(notifications.size());
        final var params = new HashMap<String, Object>();

        // Copy notifications into a list so they're accessible by index.
        final var notificationsList = List.copyOf(notifications);

        // Reduce database round-trips by concatenating the queries
        // for each notification via UNION ALL.
        for (int index = 0; index < notifications.size(); index++) {
            subQueries.add(/* language=SQL */ """
                    SELECT %d AS index
                         , "ID"
                         , "NAME"
                         , "NOTIFY_CHILDREN" AS is_notify_child_projects
                         , EXISTS(
                             SELECT 1
                               FROM "NOTIFICATIONRULE_PROJECTS"
                              WHERE "NOTIFICATIONRULE_ID" = "ID"
                           ) AS is_limited_to_projects
                         , EXISTS(
                             SELECT 1
                               FROM "NOTIFICATIONRULE_TAGS"
                              WHERE "NOTIFICATIONRULE_ID" = "ID"
                           ) AS is_limited_to_tags
                      FROM "NOTIFICATIONRULE"
                     WHERE "ENABLED"
                       AND "NOTIFICATION_LEVEL" <= :level%d
                       AND "SCOPE" = :scope%d
                       AND "NOTIFY_ON" LIKE ('%%' || :group%d || '%%')
                    """.formatted(index, index, index, index));

            final Notification notification = notificationsList.get(index);
            params.put("level" + index, convert(notification.getLevel()));
            params.put("scope" + index, convert(notification.getScope()));
            params.put("group" + index, convert(notification.getGroup()));
        }

        return jdbiHandle
                .createQuery(String.join(" UNION ALL ", subQueries))
                .bindMap(params)
                .map(ConstructorMapper.of(NotificationRuleRecord.class))
                .stream()
                .collect(Collectors.groupingBy(
                        rule -> UUID.fromString(notificationsList.get(rule.index()).getId()),
                        Collectors.toList()));
    }

    private List<Long> filterRules(
            final Notification notification,
            final List<NotificationRuleRecord> rules) {
        final Project project = extractProject(notification);
        if (project == null) {
            return rules.stream()
                    .map(NotificationRuleRecord::id)
                    .toList();
        }

        final var applicableRuleIds = new ArrayList<Long>(rules.size());

        for (final NotificationRuleRecord rule : rules) {
            try (var ignoredMdcRuleName = MDC.putCloseable("ruleName", rule.name())) {
                if (isRuleApplicable(notification, rule)) {
                    applicableRuleIds.add(rule.id());
                }
            }
        }

        return applicableRuleIds;
    }

    private boolean isRuleApplicable(
            final Notification notification,
            final NotificationRuleRecord rule) {
        if (!rule.isLimitedToProjects() && !rule.isLimitedToTags()) {
            LOGGER.debug("Rule is not limited to projects or tags: Applicable");
            return true;
        }

        if (rule.isLimitedToTags()) {
            // TODO
        }

        if (rule.isLimitedToProjects()) {
            // TODO
        }

        LOGGER.debug("Rule is not applicable");
        return false;
    }

    private Project extractProject(final Notification notification) {
        final Any subject = notification.hasSubject()
                ? notification.getSubject()
                : null;
        if (subject == null) {
            return null;
        }

        try {
            if (subject.is(BomConsumedOrProcessedSubject.class)) {
                return subject.unpack(BomConsumedOrProcessedSubject.class).getProject();
            } else if (subject.is(BomProcessingFailedSubject.class)) {
                return subject.unpack(BomProcessingFailedSubject.class).getProject();
            }
            // TODO: Add remaining subjects.
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to unpack subject", e);
        }

        return null;
    }

    private Notification deserialize(final byte[] data) {
        try {
            return Notification.parseFrom(data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


}
