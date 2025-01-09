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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.persistence.jdbi.mapping.NotificationBomRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationComponentRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationProjectRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectBomConsumedOrProcessedRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerableDependencyRowReducer;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectProjectAuditChangeRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationVulnerabilityRowMapper;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.ComponentVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jdbi.v3.core.mapper.JoinRowMapper;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMappers;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
import static org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED;

@RegisterRowMappers({
        @RegisterRowMapper(NotificationBomRowMapper.class),
        @RegisterRowMapper(NotificationComponentRowMapper.class),
        @RegisterRowMapper(NotificationProjectRowMapper.class),
        @RegisterRowMapper(NotificationVulnerabilityRowMapper.class)
})
public interface NotificationSubjectDao extends SqlObject {

    @SqlQuery("""
            SELECT
              "C"."UUID"                       AS "componentUuid",
              "C"."GROUP"                      AS "componentGroup",
              "C"."NAME"                       AS "componentName",
              "C"."VERSION"                    AS "componentVersion",
              "C"."PURL"                       AS "componentPurl",
              "C"."MD5"                        AS "componentMd5",
              "C"."SHA1"                       AS "componentSha1",
              "C"."SHA_256"                    AS "componentSha256",
              "C"."SHA_512"                    AS "componentSha512",
              "P"."UUID"                       AS "projectUuid",
              "P"."NAME"                       AS "projectName",
              "P"."VERSION"                    AS "projectVersion",
              "P"."DESCRIPTION"                AS "projectDescription",
              "P"."PURL"                       AS "projectPurl",
              (SELECT
                 ARRAY_AGG(DISTINCT "T"."NAME")
               FROM
                 "TAG" AS "T"
               INNER JOIN
                 "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
               WHERE
                 "PT"."PROJECT_ID" = "P"."ID"
              )                                AS "projectTags",
              "V"."UUID"                       AS "vulnUuid",
              "V"."VULNID"                     AS "vulnId",
              "V"."SOURCE"                     AS "vulnSource",
              "V"."TITLE"                      AS "vulnTitle",
              "V"."SUBTITLE"                   AS "vulnSubTitle",
              "V"."DESCRIPTION"                AS "vulnDescription",
              "V"."RECOMMENDATION"             AS "vulnRecommendation",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2SCORE"
                ELSE "V"."CVSSV2BASESCORE"
              END                              AS "vulnCvssV2BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3SCORE"
                ELSE "V"."CVSSV3BASESCORE"
              END                              AS "vulnCvssV3BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2VECTOR"
                ELSE "V"."CVSSV2VECTOR"
              END                              AS "vulnCvssV2Vector",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3VECTOR"
                ELSE "V"."CVSSV3VECTOR"
              END                              AS "vulnCvssV3Vector",
              -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
              --  How to handle this?
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
              END                              AS "vulnOwaspRrBusinessImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRLIKELIHOODSCORE"
              END                              AS "vulnOwaspRrLikelihoodScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
              END                              AS "vulnOwaspRrTechnicalImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPVECTOR"
                ELSE "V"."OWASPRRVECTOR"
              END                              AS "vulnOwaspRrVector",
              COALESCE("A"."SEVERITY", "V"."SEVERITY") AS "vulnSeverity",
              STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes",
              JSONB_VULN_ALIASES("V"."SOURCE", "V"."VULNID") AS "vulnAliasesJson",
              :vulnAnalysisLevel               AS "vulnAnalysisLevel",
              '/api/v1/vulnerability/source/' || "V"."SOURCE" || '/vuln/' || "V"."VULNID" || '/projects' AS "affectedProjectsApiUrl",
              '/vulnerabilities/' || "V"."SOURCE" || '/' || "V"."VULNID" || '/affectedProjects'          AS "affectedProjectsFrontendUrl"
            FROM
              "COMPONENT" AS "C"
            INNER JOIN
              "PROJECT" AS "P" ON "P"."ID" = "C"."PROJECT_ID"
            INNER JOIN
              "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."COMPONENT_ID" = "C"."ID"
            INNER JOIN
              "VULNERABILITY" AS "V" ON "V"."ID" = "CV"."VULNERABILITY_ID"
            LEFT JOIN
              "ANALYSIS" AS "A" ON "A"."COMPONENT_ID" = "C"."ID" AND "A"."VULNERABILITY_ID" = "V"."ID"
            WHERE
              "C"."UUID" = :componentUuid AND "V"."UUID" = ANY(:vulnUuids)
              AND ("A"."SUPPRESSED" IS NULL OR NOT "A"."SUPPRESSED")
            """)
    @RegisterRowMapper(NotificationSubjectNewVulnerabilityRowMapper.class)
    List<NewVulnerabilitySubject> getForNewVulnerabilities(final UUID componentUuid, final Collection<UUID> vulnUuids,
                                                           final VulnerabilityAnalysisLevel vulnAnalysisLevel);

    @SqlQuery("""
            SELECT
              "C"."UUID"                       AS "componentUuid",
              "C"."GROUP"                      AS "componentGroup",
              "C"."NAME"                       AS "componentName",
              "C"."VERSION"                    AS "componentVersion",
              "C"."PURL"                       AS "componentPurl",
              "C"."MD5"                        AS "componentMd5",
              "C"."SHA1"                       AS "componentSha1",
              "C"."SHA_256"                    AS "componentSha256",
              "C"."SHA_512"                    AS "componentSha512",
              "P"."UUID"                       AS "projectUuid",
              "P"."NAME"                       AS "projectName",
              "P"."VERSION"                    AS "projectVersion",
              "P"."DESCRIPTION"                AS "projectDescription",
              "P"."PURL"                       AS "projectPurl",
              (SELECT
                 ARRAY_AGG(DISTINCT "T"."NAME")
               FROM
                 "TAG" AS "T"
               INNER JOIN
                 "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
               WHERE
                 "PT"."PROJECT_ID" = "P"."ID"
              )                                AS "projectTags",
              "V"."UUID"                       AS "vulnUuid",
              "V"."VULNID"                     AS "vulnId",
              "V"."SOURCE"                     AS "vulnSource",
              "V"."TITLE"                      AS "vulnTitle",
              "V"."SUBTITLE"                   AS "vulnSubTitle",
              "V"."DESCRIPTION"                AS "vulnDescription",
              "V"."RECOMMENDATION"             AS "vulnRecommendation",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2SCORE"
                ELSE "V"."CVSSV2BASESCORE"
              END                              AS "vulnCvssV2BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3SCORE"
                ELSE "V"."CVSSV3BASESCORE"
              END                              AS "vulnCvssV3BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2VECTOR"
                ELSE "V"."CVSSV2VECTOR"
              END                              AS "vulnCvssV2Vector",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3VECTOR"
                ELSE "V"."CVSSV3VECTOR"
              END                              AS "vulnCvssV3Vector", 
              -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
              --  How to handle this?
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
              END                              AS "vulnOwaspRrBusinessImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRLIKELIHOODSCORE"
              END                              AS "vulnOwaspRrLikelihoodScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
              END                              AS "vulnOwaspRrTechnicalImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPVECTOR"
                ELSE "V"."OWASPRRVECTOR"
              END                              AS "vulnOwaspRrVector",
              COALESCE("A"."SEVERITY", "V"."SEVERITY") AS "vulnSeverity",
              STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes",
              JSONB_VULN_ALIASES("V"."SOURCE", "V"."VULNID") AS "vulnAliasesJson"
            FROM
              "COMPONENT" AS "C"
            INNER JOIN
              "PROJECT" AS "P" ON "P"."ID" = "C"."PROJECT_ID"
            INNER JOIN
              "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."COMPONENT_ID" = "C"."ID"
            INNER JOIN
              "VULNERABILITY" AS "V" ON "V"."ID" = "CV"."VULNERABILITY_ID"
            LEFT JOIN
              "ANALYSIS" AS "A" ON "A"."COMPONENT_ID" = "C"."ID" AND "A"."VULNERABILITY_ID" = "V"."ID"
            WHERE
              "C"."UUID" = :componentUuid
              AND ("A"."SUPPRESSED" IS NULL OR NOT "A"."SUPPRESSED")
            """)
    @UseRowReducer(NotificationSubjectNewVulnerableDependencyRowReducer.class)
    Optional<NewVulnerableDependencySubject> getForNewVulnerableDependency(final UUID componentUuid);

    @SqlQuery("""
            SELECT
              "C"."UUID"                       AS "componentUuid",
              "C"."GROUP"                      AS "componentGroup",
              "C"."NAME"                       AS "componentName",
              "C"."VERSION"                    AS "componentVersion",
              "C"."PURL"                       AS "componentPurl",
              "C"."MD5"                        AS "componentMd5",
              "C"."SHA1"                       AS "componentSha1",
              "C"."SHA_256"                    AS "componentSha256",
              "C"."SHA_512"                    AS "componentSha512",
              "P"."UUID"                       AS "projectUuid",
              "P"."NAME"                       AS "projectName",
              "P"."VERSION"                    AS "projectVersion",
              "P"."DESCRIPTION"                AS "projectDescription",
              "P"."PURL"                       AS "projectPurl",
              (SELECT
                 ARRAY_AGG(DISTINCT "T"."NAME")
               FROM
                 "TAG" AS "T"
               INNER JOIN
                 "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
               WHERE
                 "PT"."PROJECT_ID" = "P"."ID"
              )                                AS "projectTags",
              "V"."UUID"                       AS "vulnUuid",
              "V"."VULNID"                     AS "vulnId",
              "V"."SOURCE"                     AS "vulnSource",
              "V"."TITLE"                      AS "vulnTitle",
              "V"."SUBTITLE"                   AS "vulnSubTitle",
              "V"."DESCRIPTION"                AS "vulnDescription",
              "V"."RECOMMENDATION"             AS "vulnRecommendation",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2SCORE"
                ELSE "V"."CVSSV2BASESCORE"
              END                              AS "vulnCvssV2BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3SCORE"
                ELSE "V"."CVSSV3BASESCORE"
              END                              AS "vulnCvssV3BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2VECTOR"
                ELSE "V"."CVSSV2VECTOR"
              END                              AS "vulnCvssV2Vector",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3VECTOR"
                ELSE "V"."CVSSV3VECTOR"
              END                              AS "vulnCvssV3Vector",
              -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
              --  How to handle this?
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
              END                              AS "vulnOwaspRrBusinessImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRLIKELIHOODSCORE"
              END                              AS "vulnOwaspRrLikelihoodScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
              END                              AS "vulnOwaspRrTechnicalImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPVECTOR"
                ELSE "V"."OWASPRRVECTOR"
              END                              AS "vulnOwaspRrVector",
              COALESCE("A"."SEVERITY", "V"."SEVERITY") AS "vulnSeverity",
              STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes",
              JSONB_VULN_ALIASES("V"."SOURCE", "V"."VULNID") AS "vulnAliasesJson",
              :isSuppressed              AS "isVulnAnalysisSuppressed",
              :analysisState             AS "vulnAnalysisState",
              '/api/v1/vulnerability/source/' || "V"."SOURCE" || '/vuln/' || "V"."VULNID" || '/projects' AS "affectedProjectsApiUrl",
              '/vulnerabilities/' || "V"."SOURCE" || '/' || "V"."VULNID" || '/affectedProjects'          AS "affectedProjectsFrontendUrl"
            FROM
              "COMPONENT" AS "C"
            INNER JOIN
              "PROJECT" AS "P" ON "P"."ID" = "C"."PROJECT_ID"
            INNER JOIN
              "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."COMPONENT_ID" = "C"."ID"
            INNER JOIN
              "VULNERABILITY" AS "V" ON "V"."ID" = "CV"."VULNERABILITY_ID"
            LEFT JOIN
              "ANALYSIS" AS "A" ON "A"."COMPONENT_ID" = "C"."ID" AND "A"."VULNERABILITY_ID" = "V"."ID"
            WHERE
              "C"."UUID" = :componentUuid AND "V"."UUID" = :vulnUuid
            """)
    @RegisterRowMapper(NotificationSubjectProjectAuditChangeRowMapper.class)
    Optional<VulnerabilityAnalysisDecisionChangeSubject> getForProjectAuditChange(final UUID componentUuid, final UUID vulnUuid, AnalysisState analysisState, boolean isSuppressed);

    @SqlQuery("""
            SELECT "P"."UUID" AS "projectUuid"
                 , "P"."NAME"        AS "projectName"
                 , "P"."VERSION"     AS "projectVersion"
                 , "P"."DESCRIPTION" AS "projectDescription"
                 , "P"."PURL"        AS "projectPurl"
                 , (SELECT ARRAY_AGG(DISTINCT "T"."NAME")
                      FROM "TAG" AS "T"
                     INNER JOIN "PROJECTS_TAGS" AS "PT"
                        ON "PT"."TAG_ID" = "T"."ID"
                     WHERE "PT"."PROJECT_ID" = "P"."ID"
                   ) AS "projectTags"
                 , 'CycloneDX'       AS "bomFormat"
                 , 'Unknown'         AS "bomSpecVersion"
                 , '(Omitted)'       AS "bomContent"
                 , "WFS"."TOKEN"     AS "token"
              FROM "VULNERABILITYSCAN" AS "VS"
             INNER JOIN "PROJECT" AS "P"
                ON "P"."UUID" = "VS"."TARGET_IDENTIFIER"
             INNER JOIN "WORKFLOW_STATE" AS "WFS"
                ON "WFS"."TOKEN" = "VS"."TOKEN"
               AND "WFS"."STEP" = 'BOM_PROCESSING'
               AND "WFS"."STATUS" = 'COMPLETED'
             WHERE "VS"."TOKEN" = ANY(:workflowTokens)
            """)
    @RegisterRowMapper(NotificationSubjectBomConsumedOrProcessedRowMapper.class)
    List<BomConsumedOrProcessedSubject> getForDelayedBomProcessed(Collection<UUID> workflowTokens);

    @SqlQuery("""
            SELECT "P"."UUID" AS "projectUuid"
                 , "P"."NAME" AS "projectName"
                 , "P"."VERSION" AS "projectVersion"
                 , "P"."DESCRIPTION" AS "projectDescription"
                 , "P"."PURL" AS "projectPurl"
                 , (SELECT ARRAY_AGG(DISTINCT "T"."NAME")
                      FROM "TAG" AS "T"
                     INNER JOIN "PROJECTS_TAGS" AS "PT"
                        ON "PT"."TAG_ID" = "T"."ID"
                     WHERE "PT"."PROJECT_ID" = "P"."ID"
                   ) AS "projectTags"
              FROM "PROJECT" AS "P"
             WHERE "P"."UUID" = :projectUuid
            """)
    Optional<Project> getProject(UUID projectUuid);

    default Optional<ProjectVulnAnalysisCompleteSubject> getForProjectVulnAnalysisComplete(VulnerabilityScan vulnScan) {
        final Optional<Project> optionalProject = getProject(vulnScan.getTargetIdentifier());
        if (optionalProject.isEmpty()) {
            return Optional.empty();
        }

        final Map<Component, List<Vulnerability>> vulnsByComponent = getHandle().createQuery("""
                          WITH "CTE_PROJECT" AS (SELECT "ID" FROM "PROJECT" WHERE "UUID" = :projectUuid)
                        SELECT "C"."UUID" AS "componentUuid"
                             , "C"."GROUP" AS "componentGroup"
                             , "C"."NAME" AS "componentName"
                             , "C"."VERSION" AS "componentVersion"
                             , "C"."PURL" AS "componentPurl"
                             , "C"."MD5" AS "componentMd5"
                             , "C"."SHA1" AS "componentSha1"
                             , "C"."SHA_256" AS "componentSha256"
                             , "C"."SHA_512" AS "componentSha512"
                             , "V"."UUID" AS "vulnUuid"
                             , "V"."VULNID" AS "vulnId"
                             , "V"."SOURCE" AS "vulnSource"
                             , "V"."TITLE" AS "vulnTitle"
                             , "V"."SUBTITLE" AS "vulnSubTitle"
                             , "V"."DESCRIPTION" AS "vulnDescription"
                             , "V"."RECOMMENDATION" AS "vulnRecommendation"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."CVSSV2SCORE"
                                    ELSE "V"."CVSSV2BASESCORE"
                               END AS "vulnCvssV2BaseScore"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."CVSSV3SCORE"
                                    ELSE "V"."CVSSV3BASESCORE"
                               END AS "vulnCvssV3BaseScore"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."CVSSV2VECTOR"
                                    ELSE "V"."CVSSV2VECTOR"
                               END AS "vulnCvssV2Vector"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."CVSSV3VECTOR"
                                    ELSE "V"."CVSSV3VECTOR"
                               END AS "vulnCvssV3Vector"
                              -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                              --  How to handle this?
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."OWASPSCORE"
                                    ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
                               END AS "vulnOwaspRrBusinessImpactScore"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."OWASPSCORE"
                                    ELSE "V"."OWASPRRLIKELIHOODSCORE"
                               END AS "vulnOwaspRrLikelihoodScore"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."OWASPSCORE"
                                    ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
                               END AS "vulnOwaspRrTechnicalImpactScore"
                             , CASE WHEN "A"."SEVERITY" IS NOT NULL
                                    THEN "A"."OWASPVECTOR"
                                    ELSE "V"."OWASPRRVECTOR"
                               END AS "vulnOwaspRrVector"
                             , COALESCE("A"."SEVERITY", "V"."SEVERITY") AS "vulnSeverity"
                             , STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes"
                             , JSONB_VULN_ALIASES("V"."SOURCE", "V"."VULNID") AS "vulnAliasesJson"
                         FROM "COMPONENT" AS "C"
                        INNER JOIN "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."COMPONENT_ID" = "C"."ID"
                        INNER JOIN "VULNERABILITY" AS "V" ON "V"."ID" = "CV"."VULNERABILITY_ID"
                         LEFT JOIN "ANALYSIS" AS "A" ON "A"."COMPONENT_ID" = "C"."ID" AND "A"."VULNERABILITY_ID" = "V"."ID"
                        WHERE "C"."PROJECT_ID" = (SELECT "ID" FROM "CTE_PROJECT")
                          AND ("A"."SUPPRESSED" IS NULL OR NOT "A"."SUPPRESSED")
                        """)
                .bind("projectUuid", UUID.fromString(optionalProject.get().getUuid()))
                .registerRowMapper(Component.class, new NotificationComponentRowMapper())
                .registerRowMapper(Vulnerability.class, new NotificationVulnerabilityRowMapper())
                .map(JoinRowMapper.forTypes(Component.class, Vulnerability.class))
                .stream()
                .collect(Collectors.groupingBy(
                        joinRow -> joinRow.get(Component.class),
                        Collectors.mapping(joinRow -> joinRow.get(Vulnerability.class), Collectors.toList())
                ));

        final var findings = new ArrayList<ComponentVulnAnalysisCompleteSubject>(vulnsByComponent.size());
        for (final Map.Entry<Component, List<Vulnerability>> entry : vulnsByComponent.entrySet()) {
            findings.add(ComponentVulnAnalysisCompleteSubject.newBuilder()
                    .setComponent(entry.getKey())
                    .addAllVulnerabilities(entry.getValue())
                    .build());
        }

        final var subject = ProjectVulnAnalysisCompleteSubject.newBuilder()
                .setToken(String.valueOf(vulnScan.getToken()))
                .setStatus(switch (vulnScan.getStatus()) {
                    case COMPLETED -> PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
                    case FAILED -> PROJECT_VULN_ANALYSIS_STATUS_FAILED;
                    default -> throw new IllegalArgumentException("""
                            Unexpected vulnerability scan status: %s""".formatted(vulnScan.getStatus()));
                })
                .setProject(optionalProject.get())
                .addAllFindings(findings)
                .build();

        return Optional.of(subject);
    }

}
