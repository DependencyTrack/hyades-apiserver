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

import org.dependencytrack.model.Finding;
import org.dependencytrack.model.GroupedFinding;
import org.dependencytrack.persistence.jdbi.mapping.FindingRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.GroupedFindingRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

public interface FindingDao {

    @SqlQuery("""
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME"
                 , "COMPONENT"."GROUP"
                 , "COMPONENT"."VERSION"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE"
                 , "VULNERABILITY"."UUID"
                 , "VULNERABILITY"."SOURCE"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE"
                 , "VULNERABILITY"."SUBTITLE"
                 , "VULNERABILITY"."DESCRIPTION"
                 , "VULNERABILITY"."RECOMMENDATION"
                 , "VULNERABILITY"."SEVERITY"
                 , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                 , "VULNERABILITY"."CVSSV2BASESCORE"
                 , "VULNERABILITY"."CVSSV3BASESCORE"
                 , "VULNERABILITY"."CVSSV2VECTOR"
                 , "VULNERABILITY"."CVSSV3VECTOR"
                 , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                 , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRVECTOR"
                 , "EPSS"."SCORE"
                 , "EPSS"."PERCENTILE"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE"
                 , "ANALYSIS"."SUPPRESSED"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
              LEFT JOIN "EPSS"
                ON "VULNERABILITY"."VULNID" = "EPSS"."CVE"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS"
                ON "COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
              INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
             WHERE "COMPONENT"."PROJECT_ID" = :projectId
               AND (:includeSuppressed OR "ANALYSIS"."SUPPRESSED" IS NULL OR NOT "ANALYSIS"."SUPPRESSED")
            """)
    @RegisterRowMapper(FindingRowMapper.class)
    List<Finding> getFindings(@Bind long projectId, @Bind boolean includeSuppressed);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="queryFilter" type="String" -->
            SELECT "PROJECT"."UUID" AS "projectUuid"
                 , "PROJECT"."NAME" AS "projectName"
                 , "PROJECT"."VERSION" AS "projectVersion"
                 , "COMPONENT"."UUID" AS "componentUuid"
                 , "COMPONENT"."NAME"
                 , "COMPONENT"."GROUP"
                 , "COMPONENT"."VERSION"
                 , "COMPONENT"."PURL" AS "componentPurl"
                 , "COMPONENT"."CPE"
                 , "VULNERABILITY"."UUID"
                 , "VULNERABILITY"."SOURCE"
                 , "VULNERABILITY"."VULNID"
                 , "VULNERABILITY"."TITLE"
                 , "VULNERABILITY"."SUBTITLE"
                 , "VULNERABILITY"."DESCRIPTION"
                 , "VULNERABILITY"."RECOMMENDATION"
                 , "VULNERABILITY"."PUBLISHED"
                 , "VULNERABILITY"."SEVERITY"
                 , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                 , "VULNERABILITY"."CVSSV2BASESCORE"
                 , "VULNERABILITY"."CVSSV3BASESCORE"
                 , "VULNERABILITY"."CVSSV2VECTOR"
                 , "VULNERABILITY"."CVSSV3VECTOR"
                 , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                 , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                 , "VULNERABILITY"."OWASPRRVECTOR"
                 , "EPSS"."SCORE"
                 , "EPSS"."PERCENTILE"
                 , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                 , "FINDINGATTRIBUTION"."ATTRIBUTED_ON"
                 , "FINDINGATTRIBUTION"."ALT_ID"
                 , "FINDINGATTRIBUTION"."REFERENCE_URL"
                 , "ANALYSIS"."STATE"
                 , "ANALYSIS"."SUPPRESSED"
              FROM "COMPONENT"
             INNER JOIN "COMPONENTS_VULNERABILITIES"
                ON "COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID"
             INNER JOIN "VULNERABILITY"
                ON "COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
             LEFT JOIN "EPSS"
                ON "VULNERABILITY"."VULNID" = "EPSS"."CVE"
             INNER JOIN "FINDINGATTRIBUTION"
                ON "COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID"
              LEFT JOIN "ANALYSIS"
                ON "COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID"
               AND "VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID"
               AND "COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
             INNER JOIN "PROJECT"
                ON "COMPONENT"."PROJECT_ID" = "PROJECT"."ID"
             <#if queryFilter??>
                ${queryFilter}
             </#if>
            """)
    @RegisterRowMapper(FindingRowMapper.class)
    @AllowApiOrdering(alwaysBy = "\"VULNERABILITY\".\"VULNID\"", by = {
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"VULNID\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"SEVERITY\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"CVSSV2BASESCORE\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "concat(projectName, ' ', projectVersion"),
            @AllowApiOrdering.Column(name = "\"COMPONENT\".\"NAME\""),
            @AllowApiOrdering.Column(name = "\"COMPONENT\".\"VERSION\""),
            @AllowApiOrdering.Column(name = "\"ANALYSIS\".\"STATE\""),
            @AllowApiOrdering.Column(name = "\"ANALYSIS\".\"SUPPRESSED\""),
            @AllowApiOrdering.Column(name = "\"FINDINGATTRIBUTION\".\"ATTRIBUTED_ON\"")
    })
    List<Finding> getAllFindings(@Define String queryFilter);

    @SqlQuery("""
            SELECT "VULNERABILITY"."SOURCE"
                , "VULNERABILITY"."VULNID"
                , "VULNERABILITY"."TITLE"
                , "VULNERABILITY"."SEVERITY"
                , "VULNERABILITY"."CVSSV2BASESCORE"
                , "VULNERABILITY"."CVSSV3BASESCORE"
                , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
                , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
                , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
                , "VULNERABILITY"."PUBLISHED"
                , CAST(STRING_TO_ARRAY("VULNERABILITY"."CWES", ',') AS INT[]) AS "CWES"
                , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
                , COUNT(DISTINCT "PROJECT"."ID") AS "affectedProjectCount"
            FROM "COMPONENT"
                INNER JOIN "COMPONENTS_VULNERABILITIES"
                    ON ("COMPONENT"."ID" = "COMPONENTS_VULNERABILITIES"."COMPONENT_ID")
                INNER JOIN "VULNERABILITY"
                    ON ("COMPONENTS_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID")
                INNER JOIN "FINDINGATTRIBUTION"
                    ON ("COMPONENT"."ID" = "FINDINGATTRIBUTION"."COMPONENT_ID")
                    AND ("VULNERABILITY"."ID" = "FINDINGATTRIBUTION"."VULNERABILITY_ID")
                LEFT JOIN "ANALYSIS"
                    ON ("COMPONENT"."ID" = "ANALYSIS"."COMPONENT_ID")
                    AND ("VULNERABILITY"."ID" = "ANALYSIS"."VULNERABILITY_ID")
                    AND ("COMPONENT"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID")
                INNER JOIN "PROJECT"
                    ON ("COMPONENT"."PROJECT_ID" = "PROJECT"."ID")
            <#if queryFilter??>
                ${queryFilter}
            </#if>
            GROUP BY "VULNERABILITY"."ID"
               , "VULNERABILITY"."SOURCE"
               , "VULNERABILITY"."VULNID"
               , "VULNERABILITY"."TITLE"
               , "VULNERABILITY"."SEVERITY"
               , "VULNERABILITY"."CVSSV2BASESCORE"
               , "VULNERABILITY"."CVSSV3BASESCORE"
               , "VULNERABILITY"."OWASPRRLIKELIHOODSCORE"
               , "VULNERABILITY"."OWASPRRTECHNICALIMPACTSCORE"
               , "VULNERABILITY"."OWASPRRBUSINESSIMPACTSCORE"
               , "FINDINGATTRIBUTION"."ANALYZERIDENTITY"
               , "VULNERABILITY"."PUBLISHED"
               , "VULNERABILITY"."CWES"
            """)
    @RegisterRowMapper(GroupedFindingRowMapper.class)
    @AllowApiOrdering(alwaysBy = "\"VULNERABILITY\".\"VULNID\"", by = {
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"TITLE\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"SEVERITY\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"CVSSV3BASESCORE\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"CVSSV2BASESCORE\""),
            @AllowApiOrdering.Column(name = "\"VULNERABILITY\".\"PUBLISHED\""),
            @AllowApiOrdering.Column(name = "\"FINDINGATTRIBUTION\".\"ANALYZERIDENTITY\""),
            @AllowApiOrdering.Column(name = "affectedProjectCount")
    })
    List<GroupedFinding> getGroupedFindings(@Define String queryFilter);
}
