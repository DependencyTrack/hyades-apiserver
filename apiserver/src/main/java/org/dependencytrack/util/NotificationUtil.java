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
import org.dependencytrack.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.NotificationPublisher;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vex;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.publisher.DefaultNotificationPublishers;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.BomProcessingFailed;
import org.dependencytrack.notification.vo.BomValidationFailed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.FetchPlan;
import javax.jdo.Query;
import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class NotificationUtil {

    /**
     * Private constructor.
     */
    private NotificationUtil() {
    }

    public static Notification generateAnalysisNotification(final QueryManager qm, Analysis analysis,
                                                    final boolean analysisStateChange, final boolean suppressionChange) {
        // TODO: Convert data loading to raw SQL to avoid loading unneeded data and excessive queries.
        //   See #analyzeNotificationCriteria(QueryManager, PolicyViolation) for an example.
        final NotificationGroup notificationGroup;
        notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;

        String title = generateTitle(analysis.getAnalysisState(), analysis.isSuppressed(), analysisStateChange, suppressionChange);

        Project project = analysis.getComponent().getProject();

        analysis = qm.detach(Analysis.class, analysis.getId());

        analysis.getComponent().setProject(project); // Project of component is lost after the detach above

        // Aliases are lost during the detach above
        analysis.getVulnerability().setAliases(qm.detach(qm.getVulnerabilityAliases(analysis.getVulnerability())));

        return new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(notificationGroup)
                .title(generateNotificationTitle(title, analysis.getComponent().getProject()))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(analysis))
                .subject(new AnalysisDecisionChange(analysis.getVulnerability(), analysis.getComponent(), analysis.getProject(), analysis));
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

            new KafkaEventDispatcher().dispatchNotification(new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .title(generateNotificationTitle(title, violationAnalysis.getComponent().getProject()))
                    .level(NotificationLevel.INFORMATIONAL)
                    .content(generateNotificationContent(violationAnalysis))
                    .subject(new ViolationAnalysisDecisionChange(violationAnalysis.getPolicyViolation(), violationAnalysis.getComponent(), violationAnalysis)));
        }
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

        new KafkaEventDispatcher().dispatchNotification(new Notification()
                .scope(NotificationScope.PORTFOLIO)
                .group(NotificationGroup.POLICY_VIOLATION)
                .title(generateNotificationTitle(NotificationConstants.Title.POLICY_VIOLATION, project))
                .level(NotificationLevel.INFORMATIONAL)
                .content(generateNotificationContent(violation))
                .subject(new PolicyViolationIdentified(violation, component, project)));
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
            return messageType + " on Project: [" + project + "]";
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

    public static Object generateSubjectForTestRuleNotification(NotificationGroup group) {
        final Project project = createProjectForTestRuleNotification();
        final Vulnerability vuln = createVulnerabilityForTestRuleNotification();
        final Component component = createComponentForTestRuleNotification(project);
        final Analysis analysis = createAnalysisForTestRuleNotification(component, vuln);
        final PolicyViolation policyViolation = createPolicyViolationForTestRuleNotification(component, project);
        final UUID token = UUID.randomUUID();
        switch (group) {
            case BOM_CONSUMED, BOM_PROCESSED:
                return new BomConsumedOrProcessed(token, project, /* bom */ "(Omitted)", Bom.Format.CYCLONEDX, "1.5");
            case BOM_PROCESSING_FAILED:
                return new BomProcessingFailed(token, project, /* bom */ "(Omitted)", "cause", Bom.Format.CYCLONEDX, "1.5");
            case BOM_VALIDATION_FAILED:
                return new BomValidationFailed(project, /* bom */ "(Omitted)", List.of("TEST"));
            case VEX_CONSUMED, VEX_PROCESSED:
                return new VexConsumedOrProcessed(project, "", Vex.Format.CYCLONEDX, "");
            case NEW_VULNERABILITY:
                return new NewVulnerabilityIdentified(vuln, component, VulnerabilityAnalysisLevel.BOM_UPLOAD_ANALYSIS);
            case NEW_VULNERABLE_DEPENDENCY:
                return new NewVulnerableDependency(component, Set.of(vuln));
            case POLICY_VIOLATION:
                return new PolicyViolationIdentified(policyViolation, component, project);
            case PROJECT_CREATED:
                return project;
            case PROJECT_AUDIT_CHANGE:
                return new AnalysisDecisionChange(vuln, component, project, analysis);
            default:
                return null;
        }
    }

    private static Project createProjectForTestRuleNotification() {
        final Project project = new Project();
        project.setUuid(UUID.fromString("c9c9539a-e381-4b36-ac52-6a7ab83b2c95"));
        project.setName("projectName");
        project.setVersion("projectVersion");
        project.setPurl("pkg:maven/org.acme/projectName@projectVersion");
        return project;
    }

    private static Vulnerability createVulnerabilityForTestRuleNotification() {
        final Vulnerability vuln = new Vulnerability();
        vuln.setUuid(UUID.fromString("bccec5d5-ec21-4958-b3e8-22a7a866a05a"));
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.MEDIUM);
        return vuln;
    }

    private static Component createComponentForTestRuleNotification(Project project) {
        final Component component = new Component();
        component.setProject(project);
        component.setUuid(UUID.fromString("94f87321-a5d1-4c2f-b2fe-95165debebc6"));
        component.setName("componentName");
        component.setVersion("componentVersion");
        return component;
    }

    private static Analysis createAnalysisForTestRuleNotification(Component component, Vulnerability vuln) {
        final Analysis analysis = new Analysis();
        analysis.setComponent(component);
        analysis.setVulnerability(vuln);
        analysis.setAnalysisState(AnalysisState.FALSE_POSITIVE);
        analysis.setSuppressed(true);
        return analysis;
    }

    private static PolicyViolation createPolicyViolationForTestRuleNotification(Component component, Project project) {
        final Policy policy = new Policy();
        policy.setId(1);
        policy.setName("test");
        policy.setOperator(Policy.Operator.ALL);
        policy.setProjects(List.of(project));
        policy.setUuid(UUID.randomUUID());
        policy.setViolationState(Policy.ViolationState.INFO);

        final PolicyCondition condition = new PolicyCondition();
        condition.setId(1);
        condition.setUuid(UUID.randomUUID());
        condition.setOperator(PolicyCondition.Operator.NUMERIC_EQUAL);
        condition.setSubject(PolicyCondition.Subject.AGE);
        condition.setValue("1");
        condition.setPolicy(policy);

        final PolicyViolation policyViolation = new PolicyViolation();
        policyViolation.setId(1);
        policyViolation.setPolicyCondition(condition);
        policyViolation.setComponent(component);
        policyViolation.setText("test");
        policyViolation.setType(PolicyViolation.Type.SECURITY);
        policyViolation.setAnalysis(new ViolationAnalysis());
        policyViolation.setUuid(UUID.randomUUID());
        policyViolation.setTimestamp(new Date(System.currentTimeMillis()));
        return policyViolation;
    }
}
