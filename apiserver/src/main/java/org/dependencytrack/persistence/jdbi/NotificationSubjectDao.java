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

import org.dependencytrack.notification.proto.v1.Component;
import org.dependencytrack.notification.proto.v1.ComponentVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.NewVulnerableDependencySubject;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.Vulnerability;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.jdbi.mapping.NotificationBomRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationComponentRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationProjectRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectProjectAuditChangeRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.query.GetProjectAuditChangeNotificationSubjectQuery;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    default List<NewVulnerableDependencySubject> getForNewVulnerableDependencies(Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return List.of();
        }

        final var componentRowMapper = new NotificationComponentRowMapper();
        final var projectRowMapper = new NotificationProjectRowMapper();
        final var vulnerabilityRowMapper = new NotificationVulnerabilityRowMapper();
        final var subjectBuilderByComponentUuid =
                new HashMap<UUID, NewVulnerableDependencySubject.Builder>(componentIds.size());

        getHandle()
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
                          FROM "COMPONENT" AS c
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                            ON cv."COMPONENT_ID" = c."ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = cv."VULNERABILITY_ID"
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = c."ID"
                           AND a."VULNERABILITY_ID" = v."ID"
                         WHERE c."ID" = ANY(:componentIds)
                           AND EXISTS(
                                 SELECT 1
                                   FROM "FINDINGATTRIBUTION" AS fa
                                  WHERE fa."COMPONENT_ID" = c."ID"
                                    AND fa."VULNERABILITY_ID" = v."ID"
                                    AND fa."DELETED_AT" IS NULL
                               )
                           AND a."SUPPRESSED" IS DISTINCT FROM TRUE
                        """)
                .bindArray("componentIds", Long.class, componentIds)
                .reduceResultSet(subjectBuilderByComponentUuid, (accumulator, rs, ctx) -> {
                    final var componentUuid = rs.getObject("componentUuid", UUID.class);

                    NewVulnerableDependencySubject.Builder builder = accumulator.get(componentUuid);
                    if (builder == null) {
                        builder = NewVulnerableDependencySubject.newBuilder()
                                .setComponent(componentRowMapper.map(rs, ctx))
                                .setProject(projectRowMapper.map(rs, ctx));
                        accumulator.put(componentUuid, builder);
                    }

                    builder.addVulnerabilities(vulnerabilityRowMapper.map(rs, ctx));

                    return accumulator;
                });

        final var result = new ArrayList<NewVulnerableDependencySubject>(subjectBuilderByComponentUuid.size());
        subjectBuilderByComponentUuid.values().forEach(builder -> result.add(builder.build()));
        return result;
    }

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

    default Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> getForProjectVulnAnalysisComplete(
            Collection<UUID> projectUuids) {
        if (projectUuids.isEmpty()) {
            return Map.of();
        }

        final var componentRowMapper = new NotificationComponentRowMapper();
        final var vulnerabilityRowMapper = new NotificationVulnerabilityRowMapper();
        final var subjectByComponentByProject =
                new HashMap<UUID, HashMap<String, ComponentVulnAnalysisCompleteSubject.Builder>>(projectUuids.size());

        getHandle()
                .createQuery("""
                        SELECT p."UUID" AS "projectUuid"
                             , c."UUID" AS "componentUuid"
                             , c."GROUP" AS "componentGroup"
                             , c."NAME" AS "componentName"
                             , c."VERSION" AS "componentVersion"
                             , c."PURL" AS "componentPurl"
                             , c."MD5" AS "componentMd5"
                             , c."SHA1" AS "componentSha1"
                             , c."SHA_256" AS "componentSha256"
                             , c."SHA_512" AS "componentSha512"
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
                          FROM "COMPONENT" AS c
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         INNER JOIN "COMPONENTS_VULNERABILITIES" AS cv
                            ON cv."COMPONENT_ID" = c."ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = cv."VULNERABILITY_ID"
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = c."ID"
                           AND a."VULNERABILITY_ID" = v."ID"
                         WHERE p."UUID" = ANY(:projectUuids)
                           AND EXISTS(
                                 SELECT 1
                                   FROM "FINDINGATTRIBUTION" AS fa
                                  WHERE fa."COMPONENT_ID" = c."ID"
                                    AND fa."VULNERABILITY_ID" = v."ID"
                                    AND fa."DELETED_AT" IS NULL
                               )
                           AND a."SUPPRESSED" IS DISTINCT FROM TRUE
                        """)
                .bindArray("projectUuids", UUID.class, projectUuids)
                .reduceResultSet(subjectByComponentByProject, (accumulator, rs, ctx) -> {
                    final var projectUuid = rs.getObject("projectUuid", UUID.class);
                    final Component component = componentRowMapper.map(rs, ctx);
                    final Vulnerability vulnerability = vulnerabilityRowMapper.map(rs, ctx);

                    accumulator
                            .computeIfAbsent(projectUuid, k -> new HashMap<>())
                            .computeIfAbsent(
                                    component.getUuid(),
                                    k -> ComponentVulnAnalysisCompleteSubject.newBuilder()
                                            .setComponent(component))
                            .addVulnerabilities(vulnerability);

                    return accumulator;
                });

        final var result = new HashMap<UUID, List<ComponentVulnAnalysisCompleteSubject>>(subjectByComponentByProject.size());
        subjectByComponentByProject.forEach((projectUuid, componentMap) -> {
            final var findings = new ArrayList<ComponentVulnAnalysisCompleteSubject>(componentMap.size());
            componentMap.values().forEach(builder -> findings.add(builder.build()));
            result.put(projectUuid, findings);
        });

        return result;
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
