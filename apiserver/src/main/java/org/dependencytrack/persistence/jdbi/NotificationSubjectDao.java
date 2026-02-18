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

import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.jdbi.mapping.NotificationBomRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationComponentRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationProjectRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerableDependencyRowReducer;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectProjectAuditChangeRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.SequencedCollection;
import java.util.UUID;

@RegisterRowMappers({
        @RegisterRowMapper(NotificationBomRowMapper.class),
        @RegisterRowMapper(NotificationComponentRowMapper.class),
        @RegisterRowMapper(NotificationProjectRowMapper.class),
        @RegisterRowMapper(NotificationVulnerabilityRowMapper.class)
})
public interface NotificationSubjectDao extends SqlObject {

    @SqlQuery("""
            SELECT c."UUID" AS "componentUuid"
                 , c."GROUP" AS "componentGroup"
                 , c."NAME" AS "componentName"
                 , c."VERSION" AS "componentVersion"
                 , c."PURL" AS "componentPurl"
                 , c."MD5" AS "componentMd5"
                 , c."SHA1" AS "componentSha1"
                 , c."SHA_256" AS "componentSha256"
                 , c."SHA_512" AS "componentSha512"
                 , p."UUID" AS "projectUuid"
                 , p."NAME" AS "projectName"
                 , p."VERSION" AS "projectVersion"
                 , p."DESCRIPTION" AS "projectDescription"
                 , p."PURL" AS "projectPurl"
                 , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                 , (
                     SELECT ARRAY_AGG(DISTINCT t."NAME")
                       FROM "TAG" AS t
                      INNER JOIN "PROJECTS_TAGS" AS pt
                         ON pt."TAG_ID" = t."ID"
                      WHERE pt."PROJECT_ID" = p."ID"
                   ) AS "projectTags"
                 , v."UUID" AS "vulnUuid"
                 , v."VULNID" AS "vulnId"
                 , v."SOURCE" AS "vulnSource"
                 , v."TITLE" AS "vulnTitle"
                 , v."SUBTITLE" AS "vulnSubTitle"
                 , v."DESCRIPTION" AS "vulnDescription"
                 , v."RECOMMENDATION" AS "vulnRecommendation"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV2SCORE"
                     ELSE v."CVSSV2BASESCORE"
                   END AS "vulnCvssV2BaseScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV3SCORE"
                     ELSE v."CVSSV3BASESCORE"
                   END AS "vulnCvssV3BaseScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV4SCORE"
                     ELSE v."CVSSV4SCORE"
                   END AS "vulnCvssV4Score"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV2VECTOR"
                     ELSE v."CVSSV2VECTOR"
                   END AS "vulnCvssV2Vector"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV3VECTOR"
                     ELSE v."CVSSV3VECTOR"
                   END AS "vulnCvssV3Vector"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."CVSSV4VECTOR"
                     ELSE v."CVSSV4VECTOR"
                   END AS "vulnCvssV4Vector"
                  -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
                  --  How to handle this?
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                   END AS "vulnOwaspRrBusinessImpactScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRLIKELIHOODSCORE"
                   END AS "vulnOwaspRrLikelihoodScore"
                 , CASE
                     WHEN a."SEVERITY" IS NOT NULL
                     THEN a."OWASPSCORE"
                     ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                   END AS "vulnOwaspRrTechnicalImpactScore"
                 , CASE
                    WHEN a."SEVERITY" IS NOT NULL
                    THEN a."OWASPVECTOR"
                    ELSE v."OWASPRRVECTOR"
                   END AS "vulnOwaspRrVector"
                 , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                 , STRING_TO_ARRAY(v."CWES", ',') AS "vulnCwes"
                 , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
              FROM UNNEST(:componentIds, :vulnerabilityIds)
                AS req(component_id, vulnerability_id)
             INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                ON cv."COMPONENT_ID" = req.component_id
               AND cv."VULNERABILITY_ID" = req.vulnerability_id
             INNER JOIN "COMPONENT" AS c
                ON c."ID" = req.component_id
             INNER JOIN "PROJECT" AS p
                ON p."ID" = c."PROJECT_ID"
             INNER JOIN "VULNERABILITY" AS v
                ON v."ID" = req.vulnerability_id
              LEFT JOIN "ANALYSIS" AS a
                ON a."COMPONENT_ID" = req.component_id
               AND a."VULNERABILITY_ID" = req.vulnerability_id
             WHERE a."SUPPRESSED" IS DISTINCT FROM TRUE
            """)
    @RegisterRowMapper(NotificationSubjectNewVulnerabilityRowMapper.class)
    List<NewVulnerabilitySubject> getForNewVulnerabilities(List<Long> componentIds, List<Long> vulnerabilityIds);

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
              ("P"."INACTIVE_SINCE" IS NULL)   AS "isActive",
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
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV4SCORE"
                ELSE "V"."CVSSV4SCORE"
              END                              AS "vulnCvssV4Score",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2VECTOR"
                ELSE "V"."CVSSV2VECTOR"
              END                              AS "vulnCvssV2Vector",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3VECTOR"
                ELSE "V"."CVSSV3VECTOR"
              END                              AS "vulnCvssV3Vector",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV4VECTOR"
                ELSE "V"."CVSSV4VECTOR"
              END                              AS "vulnCvssV4Vector",
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
              AND "A"."SUPPRESSED" IS DISTINCT FROM TRUE
            """)
    @UseRowReducer(NotificationSubjectNewVulnerableDependencyRowReducer.class)
    Optional<NewVulnerableDependencySubject> getForNewVulnerableDependency(final UUID componentUuid);

    default List<VulnerabilityAnalysisDecisionChangeSubject> getForProjectAuditChanges(
            SequencedCollection<GetProjectAuditChangeNotificationSubjectQuery> queries) {
        if (queries.isEmpty()) {
            return List.of();
        }

        final var componentIds = new long[queries.size()];
        final var vulnDbIds = new long[queries.size()];
        final var analysisStates = new String[queries.size()];
        final var suppressions = new boolean[queries.size()];

        int i = 0;
        for (final GetProjectAuditChangeNotificationSubjectQuery query : queries) {
            componentIds[i] = query.componentId();
            vulnDbIds[i] = query.vulnId();
            analysisStates[i] = query.analysisState().name();
            suppressions[i] = query.suppressed();
            i++;
        }

        return getHandle()
                .createQuery("""
                        SELECT c."UUID" AS "componentUuid"
                             , c."GROUP" AS "componentGroup"
                             , c."NAME" AS "componentName"
                             , c."VERSION" AS "componentVersion"
                             , c."PURL" AS "componentPurl"
                             , c."MD5" AS "componentMd5"
                             , c."SHA1" AS "componentSha1"
                             , c."SHA_256" AS "componentSha256"
                             , c."SHA_512" AS "componentSha512"
                             , p."UUID" AS "projectUuid"
                             , p."NAME" AS "projectName"
                             , p."VERSION" AS "projectVersion"
                             , p."DESCRIPTION" AS "projectDescription"
                             , p."PURL" AS "projectPurl"
                             , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                             , (
                                 SELECT ARRAY_AGG(DISTINCT t."NAME")
                                   FROM "TAG" AS t
                                  INNER JOIN "PROJECTS_TAGS" AS pt
                                     ON pt."TAG_ID" = t."ID"
                                  WHERE pt."PROJECT_ID" = p."ID"
                               ) AS "projectTags"
                             , v."UUID" AS "vulnUuid"
                             , v."VULNID" AS "vulnId"
                             , v."SOURCE" AS "vulnSource"
                             , v."TITLE" AS "vulnTitle"
                             , v."SUBTITLE" AS "vulnSubTitle"
                             , v."DESCRIPTION" AS "vulnDescription"
                             , v."RECOMMENDATION" AS "vulnRecommendation"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV2SCORE"
                                 ELSE v."CVSSV2BASESCORE"
                               END AS "vulnCvssV2BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV3SCORE"
                                 ELSE v."CVSSV3BASESCORE"
                               END AS "vulnCvssV3BaseScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV4SCORE"
                                 ELSE v."CVSSV4SCORE"
                               END AS "vulnCvssV4Score"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV2VECTOR"
                                 ELSE v."CVSSV2VECTOR"
                               END AS "vulnCvssV2Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV3VECTOR"
                                 ELSE v."CVSSV3VECTOR"
                               END AS "vulnCvssV3Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."CVSSV4VECTOR"
                                 ELSE v."CVSSV4VECTOR"
                               END AS "vulnCvssV4Vector"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRBUSINESSIMPACTSCORE"
                               END AS "vulnOwaspRrBusinessImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRLIKELIHOODSCORE"
                               END AS "vulnOwaspRrLikelihoodScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPSCORE"
                                 ELSE v."OWASPRRTECHNICALIMPACTSCORE"
                               END AS "vulnOwaspRrTechnicalImpactScore"
                             , CASE
                                 WHEN a."SEVERITY" IS NOT NULL THEN a."OWASPVECTOR"
                                 ELSE v."OWASPRRVECTOR"
                               END AS "vulnOwaspRrVector"
                             , COALESCE(a."SEVERITY", v."SEVERITY") AS "vulnSeverity"
                             , STRING_TO_ARRAY(v."CWES", ',') AS "vulnCwes"
                             , JSONB_VULN_ALIASES(v."SOURCE", v."VULNID") AS "vulnAliasesJson"
                             , req.analysis_state AS "vulnAnalysisState"
                             , req.suppressed AS "isVulnAnalysisSuppressed"
                             , format('/api/v1/vulnerability/source/%s/vuln/%s/projects', v."SOURCE", v."VULNID") AS "affectedProjectsApiUrl"
                             , format('/vulnerabilities/%s/%s/affectedProjects', v."SOURCE", v."VULNID") AS "affectedProjectsFrontendUrl"
                          FROM UNNEST(:componentIds, :vulnDbIds, :analysisStates, :suppressions) WITH ORDINALITY
                            AS req(component_id, vuln_db_id, analysis_state, suppressed, ord)
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = req.component_id
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = req.vuln_db_id
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = req.component_id
                           AND a."VULNERABILITY_ID" = req.vuln_db_id
                         ORDER BY req.ord
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnDbIds", vulnDbIds)
                .bind("analysisStates", analysisStates)
                .bind("suppressions", suppressions)
                .map(new NotificationSubjectProjectAuditChangeRowMapper())
                .list();
    }

    @SqlQuery("""
            SELECT p."UUID" AS "projectUuid"
                 , p."NAME" AS "projectName"
                 , p."VERSION" AS "projectVersion"
                 , p."DESCRIPTION" AS "projectDescription"
                 , p."PURL" AS "projectPurl"
                 , (p."INACTIVE_SINCE" IS NULL) AS "isActive"
                 , (
                     SELECT ARRAY_AGG(DISTINCT t."NAME")
                       FROM "TAG" AS t
                      INNER JOIN "PROJECTS_TAGS" AS pt
                         ON pt."TAG_ID" = t."ID"
                      WHERE pt."PROJECT_ID" = p."ID"
                   ) AS "projectTags"
              FROM "PROJECT" AS p
             WHERE p."UUID" = ANY(:projectUuids)
            """)
    List<Project> getProjects(@Bind Collection<UUID> projectUuids);

}
