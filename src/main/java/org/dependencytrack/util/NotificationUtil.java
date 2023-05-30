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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.FileUtils;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.persistence.QueryManager;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class NotificationUtil {

    /**
     * Private constructor.
     */
    private NotificationUtil() {
    }

    public static void dispatchExceptionNotifications(NotificationScope scope, NotificationGroup group, String title, String content, NotificationLevel level) {
        sendNotificationToKafka(null, new Notification()
                .scope(scope)
                .group(group)
                .title(title)
                .content(content)
                .level(level)
        );
    }

    public static void dispatchNotificationsWithSubject(UUID projectUuid, NotificationScope scope, NotificationGroup group, String title, String content, NotificationLevel level, Object subject) {
        sendNotificationToKafka(projectUuid, new Notification()
                .scope(scope)
                .group(group)
                .title(title)
                .content(content)
                .level(level)
                .subject(subject)
        );
    }

    public static void analyzeNotificationCriteria(Component component, List<Vulnerability> vulnerabilities) {
        sendNotificationToKafka(component.getProject().getUuid(), new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.NEW_VULNERABLE_DEPENDENCY)
                .title(generateNotificationTitle(NotificationConstants.Title.NEW_VULNERABLE_DEPENDENCY, component.getProject()))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(vulnerabilities))
                .subject(new NewVulnerableDependency(component, vulnerabilities))
        );
    }

    public static void analyzeNotificationCriteria(UUID projectUuid, Analysis analysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;

            String title = null;
            if (analysisStateChange) {
                title = switch (analysis.getAnalysisState()) {
                    case EXPLOITABLE -> NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE;
                    case IN_TRIAGE -> NotificationConstants.Title.ANALYSIS_DECISION_IN_TRIAGE;
                    case NOT_AFFECTED -> NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED;
                    case FALSE_POSITIVE -> NotificationConstants.Title.ANALYSIS_DECISION_FALSE_POSITIVE;
                    case NOT_SET -> NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET;
                    case RESOLVED -> NotificationConstants.Title.ANALYSIS_DECISION_RESOLVED;
                };
            } else if (suppressionChange) {
                if (analysis.isSuppressed()) {
                    title = NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED;
                } else {
                    title = NotificationConstants.Title.ANALYSIS_DECISION_UNSUPPRESSED;
                }
            }

            sendNotificationToKafka(projectUuid, new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(generateNotificationTitle(title, analysis.getComponent().getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(analysis))
                    .subject(new AnalysisDecisionChange(analysis.getVulnerability(),
                            analysis.getComponent(), analysis.getProject(), analysis))
            );
        }
    }

    public static void analyzeNotificationCriteria(ViolationAnalysis violationAnalysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;
            String title = null;
            if (analysisStateChange) {
                title = switch (violationAnalysis.getAnalysisState()) {
                    case APPROVED -> NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_APPROVED;
                    case REJECTED -> NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_REJECTED;
                    case NOT_SET -> NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_NOT_SET;
                };
            } else if (suppressionChange) {
                if (violationAnalysis.isSuppressed()) {
                    title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_SUPPRESSED;
                } else {
                    title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_UNSUPPRESSED;
                }
            }

            Project project = violationAnalysis.getComponent().getProject();
            sendNotificationToKafka(project.getUuid(), new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(generateNotificationTitle(title, violationAnalysis.getComponent().getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content("An violation analysis decision was made to a policy violation affecting a project ")
                    .subject(new ViolationAnalysisDecisionChange(violationAnalysis.getPolicyViolation(),
                            violationAnalysis.getComponent(), violationAnalysis))
            );
        }
    }

    public static void analyzeNotificationCriteria(UUID projectUuid, final PolicyViolation policyViolation) {
        sendNotificationToKafka(projectUuid, new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.POLICY_VIOLATION)
                .title(generateNotificationTitle(NotificationConstants.Title.POLICY_VIOLATION, policyViolation.getComponent().getProject()))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(policyViolation))
                .subject(new PolicyViolationIdentified(policyViolation, policyViolation.getComponent(), policyViolation.getProject()))
        );
    }

    public static JsonObject toJson(final Project project) {
        final JsonObjectBuilder projectBuilder = Json.createObjectBuilder();
        projectBuilder.add("uuid", project.getUuid().toString());
        JsonUtil.add(projectBuilder, "name", project.getName());
        JsonUtil.add(projectBuilder, "version", project.getVersion());
        JsonUtil.add(projectBuilder, "description", project.getDescription());
        if (project.getPurl() != null) {
            projectBuilder.add("purl", project.getPurl().canonicalize());
        }
        if (project.getTags() != null && !project.getTags().isEmpty()) {
            final StringBuilder sb = new StringBuilder();
            for (final Tag tag : project.getTags()) {
                sb.append(tag.getName()).append(",");
            }
            String tags = sb.toString();
            if (tags.endsWith(",")) {
                tags = tags.substring(0, tags.length() - 1);
            }
            JsonUtil.add(projectBuilder, "tags", tags);
        }
        return projectBuilder.build();
    }

    public static void loadDefaultNotificationPublishers(QueryManager qm) throws IOException {
        for (final DefaultNotificationPublishers publisher : DefaultNotificationPublishers.values()) {
            File templateFile = new File(URLDecoder.decode(Objects.requireNonNull(NotificationUtil.class.getResource(publisher.getPublisherTemplateFile())).getFile(), UTF_8.name()));
            if (qm.isEnabled(ConfigPropertyConstants.NOTIFICATION_TEMPLATE_DEFAULT_OVERRIDE_ENABLED)) {
                ConfigProperty templateBaseDir = qm.getConfigProperty(
                        ConfigPropertyConstants.NOTIFICATION_TEMPLATE_BASE_DIR.getGroupName(),
                        ConfigPropertyConstants.NOTIFICATION_TEMPLATE_BASE_DIR.getPropertyName()
                );
                File userProvidedTemplateFile = new File(Path.of(templateBaseDir.getPropertyValue(), publisher.getPublisherTemplateFile()).toUri());
                if (userProvidedTemplateFile.exists()) {
                    templateFile = userProvidedTemplateFile;
                }
            }
            final String templateContent = FileUtils.readFileToString(templateFile, UTF_8);
            final NotificationPublisher existingPublisher = qm.getDefaultNotificationPublisherByName(publisher.getPublisherName());
            if (existingPublisher == null) {
                qm.createNotificationPublisher(
                        publisher.getPublisherName(), publisher.getPublisherDescription(),
                        publisher.getPublisherClass().name(), templateContent, publisher.getTemplateMimeType(),
                        publisher.isDefaultPublisher()
                );
            } else {
                existingPublisher.setName(publisher.getPublisherName());
                existingPublisher.setDescription(publisher.getPublisherDescription());
                existingPublisher.setPublisherClass(publisher.getPublisherClass().name());
                existingPublisher.setTemplate(templateContent);
                existingPublisher.setTemplateMimeType(publisher.getTemplateMimeType());
                existingPublisher.setDefaultPublisher(publisher.isDefaultPublisher());
                qm.updateNotificationPublisher(existingPublisher);
            }
        }
    }

    public static String generateNotificationContent(final Vulnerability vulnerability) {
        final String content;
        if (vulnerability.getDescription() != null) {
            content = vulnerability.getDescription();
        } else {
            content = (vulnerability.getTitle() != null) ? vulnerability.getVulnId() + ": " + vulnerability.getTitle() : vulnerability.getVulnId();
        }
        return content;
    }

    private static String generateNotificationContent(final PolicyViolation policyViolation) {
        return "A " + policyViolation.getType().name().toLowerCase() + " policy violation occurred";
    }

    private static String generateNotificationContent(final List<Vulnerability> vulnerabilities) {
        final String content;
        if (vulnerabilities.size() == 1) {
            content = "A dependency was introduced that contains 1 known vulnerability";
        } else {
            content = "A dependency was introduced that contains " + vulnerabilities.size() + " known vulnerabilities";
        }
        return content;
    }

    private static String generateNotificationContent(final Analysis analysis) {
        final String content;
        if (analysis.getProject() != null) {
            content = "An analysis decision was made to a finding affecting a project";
        } else {
            content = "An analysis decision was made to a finding on a component affecting all projects that have a dependency on the component";
        }
        return content;
    }

    public static String generateNotificationTitle(String messageType, Project project) {
        if (project != null) {
            return messageType + " on Project: [" + project.toString() + "]";
        }
        return messageType;
    }

    private static void sendNotificationToKafka(UUID projectUuid, Notification notification) {
        new KafkaEventDispatcher().dispatchAsync(projectUuid, notification);
    }
}
