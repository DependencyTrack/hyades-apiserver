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
package org.dependencytrack.util;

import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
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
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus;

import javax.jdo.FetchPlan;
import javax.jdo.Query;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
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
        // TODO: Convert data loading to raw SQL to avoid loading unneeded data and excessive queries.
        //   See #analyzeNotificationCriteria(QueryManager, PolicyViolation) for an example.
        if (analysisStateChange || suppressionChange) {
            final NotificationGroup notificationGroup;
            notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;

            String title = generateTitle(analysis.getAnalysisState(), analysis.isSuppressed(), analysisStateChange, suppressionChange);

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

    public static String generateTitle(AnalysisState analysisState, boolean isSuppressed, boolean analysisStateChange, boolean suppressionChange) {
        if (analysisStateChange) {
            return switch (analysisState) {
                case EXPLOITABLE -> NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE;
                case IN_TRIAGE -> NotificationConstants.Title.ANALYSIS_DECISION_IN_TRIAGE;
                case NOT_AFFECTED -> NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED;
                case FALSE_POSITIVE -> NotificationConstants.Title.ANALYSIS_DECISION_FALSE_POSITIVE;
                case NOT_SET -> NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET;
                case RESOLVED -> NotificationConstants.Title.ANALYSIS_DECISION_RESOLVED;
            };
        } else if (suppressionChange) {
            if (isSuppressed) {
                return NotificationConstants.Title.ANALYSIS_DECISION_SUPPRESSED;
            }

            return NotificationConstants.Title.ANALYSIS_DECISION_UNSUPPRESSED;
        }

        throw new IllegalArgumentException("""
                A title for %s notifications can only be generated if either the analysis state,
                or the suppression state has changed.""".formatted(NotificationGroup.PROJECT_AUDIT_CHANGE));
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, ViolationAnalysis violationAnalysis,
                                                   final boolean analysisStateChange, final boolean suppressionChange) {
        // TODO: Convert data loading to raw SQL to avoid loading unneeded data and excessive queries.
        //   See #analyzeNotificationCriteria(QueryManager, PolicyViolation) for an example.
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
        analyzeNotificationCriteria(qm, policyViolation.getId());
    }

    public static void analyzeNotificationCriteria(final QueryManager qm, final Long violationId) {
        final Query<?> query = qm.getPersistenceManager().newQuery(Query.SQL, """
                SELECT
                  "PV"."UUID"          AS "violationUuid",
                  "PV"."TYPE"          AS "violationType",
                  "PV"."TIMESTAMP"     AS "violationTimestamp",
                  "PC"."UUID"          AS "conditionUuid",
                  "PC"."SUBJECT"       AS "conditionSubject",
                  "PC"."OPERATOR"      AS "conditionOperator",
                  "PC"."VALUE"         AS "conditionValue",
                  "P"."UUID"           AS "policyUuid",
                  "P"."NAME"           AS "policyName",
                  "P"."VIOLATIONSTATE" AS "policyViolationState",
                  "VA"."SUPPRESSED"    AS "analysisSuppressed",
                  "VA"."STATE"         AS "analysisState",
                  "C"."UUID"           AS "componentUuid",
                  "C"."GROUP"          AS "componentGroup",
                  "C"."NAME"           AS "componentName",
                  "C"."VERSION"        AS "componentVersion",
                  "C"."PURL"           AS "componentPurl",
                  "C"."MD5"            AS "componentMd5",
                  "C"."SHA1"           AS "componentSha1",
                  "C"."SHA_256"        AS "componentSha256",
                  "C"."SHA_512"        AS "componentSha512",
                  "PR"."UUID"          AS "projectUuid",
                  "PR"."NAME"          AS "projectName",
                  "PR"."VERSION"       AS "projectVersion",
                  "PR"."DESCRIPTION"   AS "projectDescription",
                  "PR"."PURL"          AS "projectPurl",
                  (SELECT
                     STRING_AGG("T"."NAME", ',')
                   FROM
                     "TAG" AS "T"
                   INNER JOIN
                     "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
                   WHERE
                     "PT"."PROJECT_ID" = "PR"."ID"
                  )                    AS "projectTags"
                FROM
                  "POLICYVIOLATION" AS "PV"
                INNER JOIN
                  "POLICYCONDITION" AS "PC" ON "PC"."ID" = "PV"."POLICYCONDITION_ID"
                INNER JOIN
                  "POLICY" AS "P" ON "P"."ID" = "PC"."POLICY_ID"
                INNER JOIN
                  "COMPONENT" AS "C" ON "C"."ID" = "PV"."COMPONENT_ID"
                INNER JOIN
                  "PROJECT" AS "PR" ON "PR"."ID" = "PV"."PROJECT_ID"
                LEFT JOIN
                  "VIOLATIONANALYSIS" AS "VA" ON "VA"."POLICYVIOLATION_ID" = "PV"."ID"
                WHERE
                  "PV"."ID" = ?
                """);
        query.setParameters(violationId);
        final PolicyViolationNotificationProjection projection;
        try {
            projection = query.executeResultUnique(PolicyViolationNotificationProjection.class);
        } finally {
            query.closeAll();
        }

        if (projection == null) {
            return;
        }

        if ((projection.analysisSuppressed != null && projection.analysisSuppressed)
                || ViolationAnalysisState.APPROVED.name().equals(projection.analysisState)) {
            return;
        }

        final var project = new Project();
        project.setUuid(UUID.fromString(projection.projectUuid));
        project.setName(projection.projectName);
        project.setVersion(projection.projectVersion);
        project.setDescription(projection.projectDescription);
        project.setPurl(projection.projectPurl);
        project.setTags(Optional.ofNullable(projection.projectTags).stream()
                .flatMap(tagNames -> Arrays.stream(tagNames.split(",")))
                .map(StringUtils::trimToNull)
                .filter(Objects::nonNull)
                .map(tagName -> {
                    final var tag = new Tag();
                    tag.setName(tagName);
                    return tag;
                })
                .toList());

        final var component = new Component();
        component.setUuid(UUID.fromString(projection.componentUuid));
        component.setGroup(projection.componentGroup);
        component.setName(projection.componentName);
        component.setVersion(projection.componentVersion);
        component.setPurl(projection.componentPurl);
        component.setMd5(projection.componentMd5);
        component.setSha1(projection.componentSha1);
        component.setSha256(projection.componentSha256);
        component.setSha512(projection.componentSha512);

        final var policy = new Policy();
        policy.setUuid(UUID.fromString(projection.policyUuid));
        policy.setName(projection.policyName);
        policy.setViolationState(Policy.ViolationState.valueOf(projection.policyViolationState));

        final var policyCondition = new PolicyCondition();
        policyCondition.setPolicy(policy);
        policyCondition.setUuid(UUID.fromString(projection.conditionUuid));
        policyCondition.setSubject(PolicyCondition.Subject.valueOf(projection.conditionSubject));
        policyCondition.setOperator(PolicyCondition.Operator.valueOf(projection.conditionOperator));
        policyCondition.setValue(projection.conditionValue);

        final var violation = new PolicyViolation();
        violation.setPolicyCondition(policyCondition);
        violation.setUuid(UUID.fromString(projection.violationUuid));
        violation.setType(PolicyViolation.Type.valueOf(projection.violationType));
        violation.setTimestamp(projection.violationTimestamp);

        sendNotificationToKafka(project.getUuid(), new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.POLICY_VIOLATION)
                .title(generateNotificationTitle(NotificationConstants.Title.POLICY_VIOLATION, project))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(violation))
                .subject(new PolicyViolationIdentified(violation, component, project))
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

    public static String generateNotificationContent(final org.dependencytrack.proto.notification.v1.Vulnerability vulnerability) {
        final String content;
        if (vulnerability.hasDescription()) {
            content = vulnerability.getDescription();
        } else {
            content = vulnerability.hasTitle() ? vulnerability.getVulnId() + ": " + vulnerability.getTitle() : vulnerability.getVulnId();
        }
        return content;
    }

    private static String generateNotificationContent(final PolicyViolation policyViolation) {
        return "A " + policyViolation.getType().name().toLowerCase() + " policy violation occurred";
    }

    public static String generateNotificationContent(final org.dependencytrack.proto.notification.v1.Component component,
                                                     final Collection<org.dependencytrack.proto.notification.v1.Vulnerability> vulnerabilities) {
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

    public static String generateNotificationTitle(final String messageType, final org.dependencytrack.proto.notification.v1.Project project) {
        if (project == null) {
            return messageType;
        }

        // Emulate Project#toString()
        final String projectStr;
        if (project.hasPurl()) {
            projectStr = project.getPurl();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(project.getName());
            if (project.hasVersion()) {
                sb.append(" : ").append(project.getVersion());
            }
            projectStr = sb.toString();
        }

        return messageType + " on Project: [" + projectStr + "]";
    }

    private static void sendNotificationToKafka(UUID projectUuid, Notification notification) {
        new KafkaEventDispatcher().dispatchAsync(projectUuid, notification);
    }

    public static Notification createProjectVulnerabilityAnalysisCompleteNotification(VulnerabilityScan vulnScan, UUID token, ProjectVulnAnalysisStatus status) {
        // TODO: Convert data loading to raw SQL to avoid loading unneeded data and excessive queries.
        //   See #analyzeNotificationCriteria(QueryManager, PolicyViolation) for an example.
        try (QueryManager qm = new QueryManager()) {
            Project project = qm.getObjectByUuid(Project.class, vulnScan.getTargetIdentifier());
            if (project == null) {
                // This can happen when the project was deleted before completion of the vuln scan is detected.
                throw new NoSuchElementException("Project with UUID %s does not exist".formatted(vulnScan.getTargetIdentifier()));
            }

            List<Finding> findings = qm.getFindings(project);
            List<Component> componentList = new ArrayList<>();
            ConcurrentHashMap<String, List<Vulnerability>> map = new ConcurrentHashMap<>();
            for (Finding finding : findings) {
                final var componentUuid = (String) finding.getComponent().get("uuid");
                Component component = qm.getObjectByUuid(Component.class, componentUuid);
                if (component == null) {
                    // This can happen when the project was deleted while this method is executing.
                    throw new NoSuchElementException("Component with UUID %s does not exist in project %s"
                            .formatted(componentUuid, project.getUuid()));
                }
                final var vulnerabilityUuid = (String) finding.getVulnerability().get("uuid");
                Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, vulnerabilityUuid);
                if (vulnerability == null) {
                    // Unlikely to happen, but when in doubt it's still better to raise this exception
                    // instead of running into a generic NPE.
                    throw new NoSuchElementException("Vulnerability with UUID %s does not exist".formatted(vulnerabilityUuid));
                }
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
                    .subject(new ProjectVulnAnalysisComplete(token, project, componentAnalysisCompleteList, status));
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
                vulnerability1.setTitle(vulnerability.getTitle());
                vulnerability1.setSubTitle(vulnerability.getSubTitle());
                vulnerability1.setRecommendation(vulnerability.getRecommendation());
                vulnerability1.setSeverity(vulnerability.getSeverity());
                vulnerability1.setCvssV2BaseScore(vulnerability.getCvssV2BaseScore());
                vulnerability1.setCvssV3BaseScore(vulnerability.getCvssV3BaseScore());
                vulnerability1.setOwaspRRLikelihoodScore(vulnerability.getOwaspRRLikelihoodScore());
                vulnerability1.setOwaspRRTechnicalImpactScore(vulnerability.getOwaspRRTechnicalImpactScore());
                vulnerability1.setOwaspRRBusinessImpactScore(vulnerability.getOwaspRRBusinessImpactScore());
                vulnerability1.setCwes(vulnerability.getCwes());
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

    public static class PolicyViolationNotificationProjection {
        public String projectUuid;
        public String projectName;
        public String projectVersion;
        public String projectDescription;
        public String projectPurl;
        public String projectTags;
        public String componentUuid;
        public String componentGroup;
        public String componentName;
        public String componentVersion;
        public String componentPurl;
        public String componentMd5;
        public String componentSha1;
        public String componentSha256;
        public String componentSha512;
        public String violationUuid;
        public String violationType;
        public Date violationTimestamp;
        public String conditionUuid;
        public String conditionSubject;
        public String conditionOperator;
        public String conditionValue;
        public String policyUuid;
        public String policyName;
        public String policyViolationState;
        public Boolean analysisSuppressed;
        public String analysisState;
    }

}
