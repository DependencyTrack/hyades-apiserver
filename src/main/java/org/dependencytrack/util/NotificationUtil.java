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
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.ComponentVulnAnalysisComplete;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.ProjectVulnAnalysisComplete;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.persistence.QueryManager;
import org.hyades.proto.notification.v1.ProjectVulnAnalysisStatus;

import javax.jdo.FetchPlan;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

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

    public static void analyzeNotificationCriteria(final QueryManager qm, Analysis analysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;

            String title = null;
            if (analysisStateChange) {
                switch (analysis.getAnalysisState()) {
                    case EXPLOITABLE:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE;
                        break;
                    case IN_TRIAGE:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_IN_TRIAGE;
                        break;
                    case NOT_AFFECTED:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED;
                        break;
                    case FALSE_POSITIVE:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_FALSE_POSITIVE;
                        break;
                    case NOT_SET:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET;
                        break;
                    case RESOLVED:
                        title = NotificationConstants.Title.ANALYSIS_DECISION_RESOLVED;
                        break;
                }
            } else if (suppressionChange) {
                if (analysis.isSuppressed()) {
                    title = NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED;
                } else {
                    title = NotificationConstants.Title.ANALYSIS_DECISION_UNSUPPRESSED;
                }
            }

            Project project = analysis.getComponent().getProject();

            analysis = qm.detach(Analysis.class, analysis.getId());

            analysis.getComponent().setProject(project); // Project of component is lost after the detach above

            // Aliases are lost during the detach above
            analysis.getVulnerability().setAliases(qm.detach(qm.getVulnerabilityAliases(analysis.getVulnerability())));

            sendNotificationToKafka(project.getUuid(), new Notification()
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

    public static void analyzeNotificationCriteria(final QueryManager qm, ViolationAnalysis violationAnalysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;
            String title = null;
            if (analysisStateChange) {
                switch (violationAnalysis.getAnalysisState()) {
                    case APPROVED:
                        title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_APPROVED;
                        break;
                    case REJECTED:
                        title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_REJECTED;
                        break;
                    case NOT_SET:
                        title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_NOT_SET;
                        break;
                }
            } else if (suppressionChange) {
                if (violationAnalysis.isSuppressed()) {
                    title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_SUPPRESSED;
                } else {
                    title = NotificationConstants.Title.VIOLATIONANALYSIS_DECISION_UNSUPPRESSED;
                }
            }

            Project project = violationAnalysis.getComponent().getProject();
            PolicyViolation policyViolation = violationAnalysis.getPolicyViolation();
            violationAnalysis.getPolicyViolation().getPolicyCondition().getPolicy(); // Force loading of policy

            // Detach policyViolation, ensuring that all elements in the policyViolation->policyCondition->policy
            // reference chain are included. It's important that "the opposite way" is not loaded when detaching,
            // otherwise the policy->policyConditions reference chain will cause indefinite recursion issues during
            // JSON serialization.
            final int origMaxFetchDepth = qm.getPersistenceManager().getFetchPlan().getMaxFetchDepth();
            final int origDetachmentOptions = qm.getPersistenceManager().getFetchPlan().getDetachmentOptions();
            try {
                qm.getPersistenceManager().getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
                qm.getPersistenceManager().getFetchPlan().setMaxFetchDepth(2);
                policyViolation = qm.getPersistenceManager().detachCopy(policyViolation);
            } finally {
                qm.getPersistenceManager().getFetchPlan().setDetachmentOptions(origDetachmentOptions);
                qm.getPersistenceManager().getFetchPlan().setMaxFetchDepth(origMaxFetchDepth);
            }

            violationAnalysis = qm.detach(ViolationAnalysis.class, violationAnalysis.getId());

            violationAnalysis.getComponent().setProject(project); // Project of component is lost after the detach above
            violationAnalysis.setPolicyViolation(policyViolation); // PolicyCondition and policy of policyViolation is lost after the detach above

            sendNotificationToKafka(project.getUuid(), new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(generateNotificationTitle(title, violationAnalysis.getComponent().getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(violationAnalysis))
                    .subject(new ViolationAnalysisDecisionChange(violationAnalysis.getPolicyViolation(),
                            violationAnalysis.getComponent(), violationAnalysis))
            );
        }
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, final PolicyViolation policyViolation) {
        final ViolationAnalysis violationAnalysis = qm.getViolationAnalysis(policyViolation.getComponent(), policyViolation);
        if (violationAnalysis != null && (violationAnalysis.isSuppressed() || ViolationAnalysisState.APPROVED == violationAnalysis.getAnalysisState()))
            return;
        policyViolation.getPolicyCondition().getPolicy(); // Force loading of policy
        qm.getPersistenceManager().getFetchPlan().setMaxFetchDepth(2); // Ensure policy is included
        qm.getPersistenceManager().getFetchPlan().setDetachmentOptions(FetchPlan.DETACH_LOAD_FIELDS);
        final PolicyViolation pv = qm.getPersistenceManager().detachCopy(policyViolation);
        Project project = policyViolation.getComponent().getProject();
        sendNotificationToKafka(project.getUuid(), new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.POLICY_VIOLATION)
                .title(generateNotificationTitle(NotificationConstants.Title.POLICY_VIOLATION, policyViolation.getComponent().getProject()))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(pv))
                .subject(new PolicyViolationIdentified(pv, pv.getComponent(), pv.getProject()))
        );
    }

    public static void loadDefaultNotificationPublishers(QueryManager qm) throws IOException {
        for (final DefaultNotificationPublishers publisher : DefaultNotificationPublishers.values()) {
            File templateFile = new File(URLDecoder.decode(NotificationUtil.class.getResource(publisher.getPublisherTemplateFile()).getFile(), UTF_8.name()));
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

    public static String generateNotificationContent(final Component component, final Set<Vulnerability> vulnerabilities) {
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

    private static String generateNotificationContent(final ViolationAnalysis violationAnalysis) {
        return "An violation analysis decision was made to a policy violation affecting a project";
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

    public static Notification createProjectVulnerabilityAnalysisCompleteNotification(VulnerabilityScan vulnscan, ProjectVulnAnalysisStatus status) {
        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, vulnscan.getTargetIdentifier());
            List<Finding> findings = qm.getFindings(project);
            List<Component> componentList = new ArrayList<>();
            ConcurrentHashMap<String, List<Vulnerability>> map = new ConcurrentHashMap<>();
            for (Finding finding : findings) {
                Component component = qm.getObjectByUuid(Component.class, (String) finding.getComponent().get("uuid"));
                Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, (String) finding.getVulnerability().get("uuid"));
                final List<VulnerabilityAlias> aliases = qm.detach(qm.getVulnerabilityAliases(vulnerability));
                vulnerability.setAliases(aliases);
                if (map.containsKey(component.getUuid().toString())) {
                    List<Vulnerability> temp1 = new ArrayList<>();
                    temp1.add(vulnerability);
                    temp1.addAll(map.get(component.getUuid().toString()));
                    map.remove(component.getUuid().toString());
                    map.put(component.getUuid().toString(), temp1);
                } else {
                    //component should be added to list only if not present in map
                    componentList.add(component);
                    map.put(component.getUuid().toString(), List.of(vulnerability));
                }
            }


            List<ComponentVulnAnalysisComplete> componentAnalysisCompleteList = createList(componentList, map);
            return new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(NotificationGroup.PROJECT_VULN_ANALYSIS_COMPLETE)
                    .level(NotificationLevel.INFORMATIONAL)
                    .title(NotificationConstants.Title.PROJECT_VULN_ANALYSIS_COMPLETE)
                    .content("project analysis complete for project " + project.getName() + " with id: " + project.getUuid() + " and with version: " + project.getVersion() + ". Vulnerability details added to subject ")
                    .subject(new ProjectVulnAnalysisComplete(project, componentAnalysisCompleteList, status));
        }
    }

    public static List<ComponentVulnAnalysisComplete> createList(List<Component> componentList, Map<String, List<Vulnerability>> map) {
        List<ComponentVulnAnalysisComplete> componentAnalysisCompleteList = new ArrayList<>();
        for (Component component : componentList) {
            List<Vulnerability> vulnerabilities = map.get(component.getUuid().toString());
            List<Vulnerability> result = new ArrayList<>();
            for (Vulnerability vulnerability : vulnerabilities) {
                Vulnerability vulnerability1 = new Vulnerability();
                vulnerability1.setId(vulnerability.getId());
                vulnerability1.setVulnId(vulnerability.getVulnId());
                vulnerability1.setSource(vulnerability.getSource());
                vulnerability1.setOwaspRRBusinessImpactScore(vulnerability.getOwaspRRBusinessImpactScore());
                vulnerability1.setTitle(vulnerability.getTitle());
                vulnerability1.setSubTitle(vulnerability.getSubTitle());
                vulnerability1.setRecommendation(vulnerability.getRecommendation());
                vulnerability1.setCvssV2BaseScore(vulnerability.getCvssV2BaseScore());
                vulnerability1.setCvssV3BaseScore(vulnerability.getCvssV3BaseScore());
                vulnerability1.setSeverity(vulnerability.getSeverity());
                vulnerability1.setCwes(vulnerability.getCwes());
                vulnerability1.setOwaspRRLikelihoodScore(vulnerability.getOwaspRRLikelihoodScore());
                vulnerability1.setOwaspRRTechnicalImpactScore(vulnerability.getOwaspRRTechnicalImpactScore());
                vulnerability1.setOwaspRRBusinessImpactScore(vulnerability.getOwaspRRBusinessImpactScore());
                vulnerability1.setUuid(vulnerability.getUuid());
                vulnerability1.setVulnerableSoftware(vulnerability.getVulnerableSoftware());
                if (vulnerability.getAliases() != null && !vulnerability.getAliases().isEmpty()) {
                    vulnerability1.setAliases(vulnerability.getAliases());
                }
                result.add(vulnerability1);
            }
            componentAnalysisCompleteList.add(new ComponentVulnAnalysisComplete(result, component));
        }
        return componentAnalysisCompleteList;
    }
}
