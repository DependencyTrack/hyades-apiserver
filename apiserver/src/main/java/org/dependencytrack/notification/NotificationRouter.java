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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.dependencytrack.common.MdcScope;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.BomProcessingFailedSubject;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.notification.v1.VexConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;

/**
 * @since 5.7.0
 */
final class NotificationRouter {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationRouter.class.getName());

    private final Handle jdbiHandle;
    private final Timer ruleQueryLatency;
    private final Timer ruleFilterLatency;
    private final MeterProvider<Counter> rulesMatchedCounter;

    NotificationRouter(
            final Handle jdbiHandle,
            final MeterRegistry meterRegistry) {
        this.jdbiHandle = requireNonNull(jdbiHandle, "jdbiHandle must not be null");
        requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.ruleQueryLatency = Timer
                .builder("dtrack.notification.router.rule.query.latency")
                .description("Latency of applicable notification rule queries")
                .register(meterRegistry);
        this.ruleFilterLatency = Timer
                .builder("dtrack.notification.router.rule.filter.latency")
                .description("Latency of applicable notification rule filtering")
                .register(meterRegistry);
        this.rulesMatchedCounter = Counter
                .builder("dtrack.notification.router.rules.matched")
                .description("Number of matched notification rules")
                .withRegistry(meterRegistry);
    }

    List<NotificationPublishTask> route(final Collection<Notification> notifications) {
        requireNonNull(notifications, "notifications must not be null");
        if (notifications.isEmpty()) {
            return Collections.emptyList();
        }

        final Timer.Sample ruleQueryLatencySample = Timer.start();
        final Map<Notification, List<RuleQueryResult>> rulesByNotification;
        try {
            rulesByNotification = queryRules(notifications);
        } finally {
            ruleQueryLatencySample.stop(ruleQueryLatency);
        }

        if (rulesByNotification.isEmpty()) {
            LOGGER.debug("None of the provided {} notifications have any matching rules", notifications.size());
            return Collections.emptyList();
        }

        final var publishTasks = new ArrayList<NotificationPublishTask>(rulesByNotification.size());

        for (final Map.Entry<Notification, List<RuleQueryResult>> entry : rulesByNotification.entrySet()) {
            final Notification notification = entry.getKey();
            final List<RuleQueryResult> rules = entry.getValue();

            try (var ignoredMdcScope = new MdcScope(Map.ofEntries(
                    Map.entry("notificationId", notification.getId()),
                    Map.entry("notificationScope", convert(notification.getScope()).name()),
                    Map.entry("notificationGroup", convert(notification.getGroup()).name()),
                    Map.entry("notificationLevel", convert(notification.getLevel()).name())))) {
                final Timer.Sample ruleFilterLatencySample = Timer.start();
                final List<RuleQueryResult> applicableRules;
                try {
                    applicableRules = maybeFilterRules(notification, rules);
                } finally {
                    ruleFilterLatencySample.stop(ruleFilterLatency);
                }

                for (final RuleQueryResult rule : applicableRules) {
                    LOGGER.debug("Adding publish task for rule {}", rule.name());
                    rulesMatchedCounter.withTag("ruleName", rule.name()).increment();
                    publishTasks.add(new NotificationPublishTask(rule.id(), rule.name(), notification));
                }
            }
        }

        return publishTasks;
    }

    public record RuleQueryResult(
            int notificationIndex,
            long id,
            String name,
            boolean isNotifyChildProjects,
            Set<String> limitToProjectUuids,
            Set<String> limitToTagNames) {

        private boolean isLimitedToProjects() {
            return limitToProjectUuids != null && !limitToProjectUuids.isEmpty();
        }

        private boolean isLimitedToTags() {
            return limitToTagNames != null && !limitToTagNames.isEmpty();
        }

    }

    private Map<Notification, List<RuleQueryResult>> queryRules(
            final Collection<Notification> notifications) {
        // Copy notifications into a list so they're accessible by index.
        final var notificationsList = List.copyOf(notifications);

        final var indexes = new int[notificationsList.size()];
        final var scopes = new NotificationScope[notificationsList.size()];
        final var groups = new NotificationGroup[notificationsList.size()];
        final var levels = new NotificationLevel[notificationsList.size()];

        for (int i = 0; i < notificationsList.size(); i++) {
            final Notification notification = notificationsList.get(i);
            indexes[i] = i;
            scopes[i] = convert(notification.getScope());
            groups[i] = convert(notification.getGroup());
            levels[i] = convert(notification.getLevel());
        }

        // Retrieve potentially matching rules for all notifications at once.
        // Keep track of which result was returned for which notification via
        // the notification's index.
        //
        // Note that this can potentially return redundant data, say when all
        // notifications yield the same N results. In such cases it might be
        // more efficient to query the rule IDs first, and then retrieve more
        // rule information separately. We leave that for a future optimisation.
        final Query query = jdbiHandle.createQuery("""
                SELECT t.index AS notification_index
                     , rule."ID"
                     , rule."NAME"
                     , rule."NOTIFY_CHILDREN" AS is_notify_child_projects
                     , (
                         SELECT ARRAY_AGG("PROJECT"."UUID")
                           FROM "NOTIFICATIONRULE_PROJECTS"
                          INNER JOIN "PROJECT"
                             ON "PROJECT"."ID" = "NOTIFICATIONRULE_PROJECTS"."PROJECT_ID"
                          WHERE "NOTIFICATIONRULE_ID" = rule."ID"
                       ) AS limit_to_project_uuids
                     , (
                         SELECT ARRAY_AGG("TAG"."NAME")
                           FROM "NOTIFICATIONRULE_TAGS"
                          INNER JOIN "TAG"
                             ON "TAG"."ID" = "NOTIFICATIONRULE_TAGS"."TAG_ID"
                          WHERE "NOTIFICATIONRULE_ID" = rule."ID"
                       ) AS limit_to_tag_names
                  FROM UNNEST(:indexes, :scopes, :levels, :groups)
                    AS t(index, scope, level, "group")
                 INNER JOIN "NOTIFICATIONRULE" AS rule
                    ON rule."SCOPE" = t.scope
                   AND rule."NOTIFY_ON" LIKE ('%' || t."group" || '%')
                   AND rule."NOTIFICATION_LEVEL" <= t.level
                 WHERE rule."ENABLED"
                """);

        return query
                // Ensure level is cast to its corresponding enum type in the database.
                // Necessary to support the <= comparison.
                .registerArrayType(NotificationLevel.class, "notification_level")
                .bind("indexes", indexes)
                .bind("scopes", scopes)
                .bind("groups", groups)
                .bind("levels", levels)
                .map(ConstructorMapper.of(RuleQueryResult.class))
                .stream()
                .collect(Collectors.groupingBy(
                        rule -> notificationsList.get(rule.notificationIndex()),
                        Collectors.toList()));
    }

    private List<RuleQueryResult> maybeFilterRules(
            final Notification notification,
            final List<RuleQueryResult> ruleCandidates) {
        final Project projectSubject = getProjectSubject(notification);
        if (projectSubject == null) {
            LOGGER.debug("Notification can't be filtered; All rules are applicable");
            return ruleCandidates;
        }

        final var applicableRules = new ArrayList<RuleQueryResult>(ruleCandidates.size());
        for (final RuleQueryResult rule : ruleCandidates) {
            try (var ignoredMdcRuleName = MDC.putCloseable("notificationRuleName", rule.name())) {
                if (isApplicable(rule, projectSubject)) {
                    LOGGER.debug("Rule is applicable");
                    applicableRules.add(rule);
                } else {
                    LOGGER.debug("Rule is not applicable");
                }
            }
        }

        return applicableRules;
    }

    private boolean isApplicable(final RuleQueryResult rule, final Project project) {
        // TODO: It should be possible to allow for custom filtering using CEL.
        //  This would address feature requests such as https://github.com/DependencyTrack/dependency-track/issues/3767.
        //  Since notifications are already well-defined Protobuf messages,
        //  it would be relatively easy to implement.

        if (!rule.isLimitedToProjects() && !rule.isLimitedToTags()) {
            LOGGER.debug("Rule is not limited to projects or tags");
            return true;
        }

        // Tag matching is cheaper to perform since it doesn't require additional
        // database interactions, so do it first.
        if (rule.isLimitedToTags()) {
            LOGGER.debug("Rule is limited to tags: {}", rule.limitToTagNames());

            final String matchedTagName = project.getTagsList().stream()
                    .filter(rule.limitToTagNames()::contains)
                    .findAny()
                    .orElse(null);
            if (matchedTagName != null) {
                LOGGER.debug("Rule matched project on tag {}", matchedTagName);
                return true;
            } else {
                LOGGER.debug("Rule did not match any project tag");
                return false;
            }
        }

        if (rule.isLimitedToProjects()) {
            LOGGER.debug("Rule is limited to projects with UUIDs: {}", rule.limitToProjectUuids());

            if (rule.limitToProjectUuids().contains(project.getUuid())) {
                LOGGER.debug("Rule matched project on UUID: {}", project.getUuid());
                return true;
            } else if (rule.isNotifyChildProjects()) {
                LOGGER.debug("Rule did not match on any project UUID");
                if (isChildOfAnyActiveParent(rule.limitToProjectUuids(), project.getUuid())) {
                    LOGGER.debug("Rule matched parents of project");
                    return true;
                } else {
                    LOGGER.debug("""
                            Rule did not match: Project {} is not a child of any \
                            specified parent projects""", project.getUuid());
                    return false;
                }
            }
        }

        return false;
    }

    private Project getProjectSubject(final Notification notification) {
        if (notification.getScope() != SCOPE_PORTFOLIO
                || !notification.hasSubject()) {
            return null;
        }

        try {
            return switch (notification.getGroup()) {
                case GROUP_BOM_CONSUMED, GROUP_BOM_PROCESSED -> notification.getSubject().unpack(
                        BomConsumedOrProcessedSubject.class).getProject();
                case GROUP_BOM_PROCESSING_FAILED -> notification.getSubject().unpack(
                        BomProcessingFailedSubject.class).getProject();
                case GROUP_BOM_VALIDATION_FAILED -> notification.getSubject().unpack(
                        BomValidationFailedSubject.class).getProject();
                case GROUP_NEW_VULNERABILITY -> notification.getSubject().unpack(
                        NewVulnerabilitySubject.class).getProject();
                case GROUP_NEW_VULNERABLE_DEPENDENCY -> notification.getSubject().unpack(
                        NewVulnerableDependencySubject.class).getProject();
                case GROUP_POLICY_VIOLATION -> notification.getSubject().unpack(
                        PolicyViolationSubject.class).getProject();
                case GROUP_PROJECT_AUDIT_CHANGE -> {
                    if (notification.getSubject().is(
                            PolicyViolationAnalysisDecisionChangeSubject.class)) {
                        yield notification.getSubject().unpack(
                                PolicyViolationAnalysisDecisionChangeSubject.class).getProject();
                    } else if (notification.getSubject().is(
                            VulnerabilityAnalysisDecisionChangeSubject.class)) {
                        yield notification.getSubject().unpack(
                                VulnerabilityAnalysisDecisionChangeSubject.class).getProject();
                    }
                    throw new IllegalStateException("Unexpected subject for group %s: %s".formatted(
                            notification.getGroup(), notification.getSubject().getTypeUrl()));
                }
                case GROUP_PROJECT_CREATED -> notification.getSubject().unpack(Project.class);
                case GROUP_PROJECT_VULN_ANALYSIS_COMPLETE -> notification.getSubject().unpack(
                        ProjectVulnAnalysisCompleteSubject.class).getProject();
                case GROUP_VEX_CONSUMED, GROUP_VEX_PROCESSED -> notification.getSubject().unpack(
                        VexConsumedOrProcessedSubject.class).getProject();
                default -> null;
            };
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to unpack subject", e);
        }
    }

    private boolean isChildOfAnyActiveParent(final Collection<String> parentUuids, final String childUuid) {
        final Query query = jdbiHandle.createQuery("""
                SELECT EXISTS(
                  SELECT 1
                    FROM "PROJECT_HIERARCHY" AS hierarchy
                   INNER JOIN "PROJECT" AS parent_project
                      ON parent_project."ID" = hierarchy."PARENT_PROJECT_ID"
                   INNER JOIN "PROJECT" AS child_project
                      ON child_project."ID" = hierarchy."CHILD_PROJECT_ID"
                   WHERE parent_project."UUID" = ANY(CAST(:parentUuids AS UUID[]))
                     AND parent_project."INACTIVE_SINCE" IS NULL
                     AND child_project."UUID" = CAST(:childUuid AS UUID)
                )
                """);

        return query
                .bindArray("parentUuids", String.class, parentUuids)
                .bind("childUuid", childUuid)
                .mapTo(boolean.class)
                .one();
    }

}
