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

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.notification.NotificationEmitter;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.Query;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.notification.ModelConverter.convert;
import static org.dependencytrack.notification.NotificationFactory.createPolicyViolationNotification;

public final class NotificationUtil {

    /**
     * Private constructor.
     */
    private NotificationUtil() {
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
                .collect(Collectors.toSet()));

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

        NotificationEmitter.using(qm).emit(
                createPolicyViolationNotification(
                        convert(project),
                        convert(component),
                        convert(violation)));
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
