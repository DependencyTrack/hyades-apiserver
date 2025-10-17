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

import org.dependencytrack.model.Advisory;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.AllowUnusedBindings;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

/**
 * JDBI Data Access Object for performing operations on {@link Advisory} objects.
 */
public interface AdvisoryDao {

    /**
     * A row representing an advisory with findings in a specific project.
     *
     * @param name
     * @param projectId
     * @param url
     * @param documentId
     * @param findingsPerDoc
     */
    record AdvisoryInProjectRow(
            String name,
            int projectId,
            String url,
            int documentId,
            int findingsPerDoc
    ) {
    }

    record VulnerabilityRow(
            String id,
            String source,
            String vulnId
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "TITLE" AS "name"
                 , "PROJECT_ID" AS "projectId"
                 , "URL" AS "url"
                 , "ADVISORY_ID" AS "documentId"
                 , COUNT("FINDINGATTRIBUTION"."ID") AS "findingsPerDoc"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "ADVISORIES_VULNERABILITIES"
               ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            INNER JOIN "ADVISORY" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            WHERE "PROJECT_ID" = :projectId
            GROUP BY "ADVISORY_ID", "TITLE", "URL", "PROJECT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryInProjectRow.class)
    List<AdvisoryInProjectRow> getAdvisoriesWithFindingsByProject(@Bind long projectId, @Bind boolean suppressed);

    record AdvisoryResult(
            Advisory entity,
            List<ProjectRow> affectedProjects,
            long numAffectedComponents,
            List<AdvisoryDao.VulnerabilityRow> vulnerabilities
    ) {
    }

    record ProjectRow(
            int id,
            String name,
            String uuid,
            String desc,
            String version
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT DISTINCT "PROJECT_ID" AS "id",
            "PROJECT"."NAME" AS "name",
            "PROJECT"."UUID" AS "uuid",
            "PROJECT"."DESCRIPTION" AS "desc",
            "PROJECT"."VERSION" AS "version"
            --Latest,Classifier,Last BOM Import,BOM Format,Risk Score,Active,Policy Violations,Vulnerabilities
            
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "ADVISORIES_VULNERABILITIES"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            INNER JOIN "ADVISORY" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            INNER JOIN "PROJECT" ON "PROJECT_ID" = "PROJECT"."ID"
            WHERE "ADVISORY_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.ProjectRow.class)
    List<ProjectRow> getProjectsByAdvisory(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT DISTINCT "VULNERABILITY"."ID" AS "id",
            "SOURCE" AS "source",
            "VULNID" AS "vulnId"
            
            FROM "ADVISORIES_VULNERABILITIES"
            INNER JOIN "ADVISORY" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            INNER JOIN "VULNERABILITY" ON "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
            WHERE "ADVISORY_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.VulnerabilityRow.class)
    List<VulnerabilityRow> getVulnerabilitiesByAdvisory(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT COALESCE(COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID"), 0) AS "findingsWithAnalysis"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "ADVISORIES_VULNERABILITIES"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            INNER JOIN "ANALYSIS" ON
            "FINDINGATTRIBUTION"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
            WHERE "ADVISORY_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    Long getAmountFindingsMarked(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT COALESCE(COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID"), 0) AS "findingsWithAnalysis"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "ADVISORIES_VULNERABILITIES"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            WHERE "ADVISORY_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    Long getAmountFindingsTotal(long advisoryId);

    record AdvisoriesPortfolioRow(
            String name,
            int affectedComponents,
            int affectedProjects,
            String url,
            int documentId
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->

            SELECT "ADVISORY"."TITLE" as "name",
            COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID") AS "affectedComponents",
            COUNT(DISTINCT "PROJECT_ID") AS "affectedProjects",
            "URL" AS "url",
            "ADVISORY"."ID" AS "documentId"
            FROM "ADVISORY"
            LEFT JOIN "ADVISORIES_VULNERABILITIES" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            LEFT JOIN "FINDINGATTRIBUTION" ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            WHERE (:searchTerm IS NULL OR :searchTerm = '' OR LOWER("ADVISORY"."TITLE") LIKE CONCAT('%', LOWER(:searchTerm), '%'))
            GROUP BY "ADVISORY"."ID","ADVISORY"."TITLE","URL"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoriesPortfolioRow.class)
    List<AdvisoriesPortfolioRow> getAllAdvisories(@Bind("searchTerm") String searchTerm);

    @AllowUnusedBindings
    @SqlQuery(/* language=InjectedFreeMarker */ """            
            SELECT COALESCE(COUNT(DISTINCT "ADVISORY"."ID"), 0) as "totalCount"
            FROM "ADVISORY"
            LEFT JOIN "ADVISORIES_VULNERABILITIES" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            LEFT JOIN "FINDINGATTRIBUTION" ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            WHERE (:searchTerm IS NULL OR :searchTerm = '' OR LOWER("ADVISORY"."TITLE") LIKE CONCAT('%', LOWER(:searchTerm), '%'))
            """)
    long getAllAdvisoriesTotal(@Bind("searchTerm") String searchTerm);

    record ProjectAdvisoryFinding(
            String name,
            float confidence,
            String desc,
            String group,
            String version,
            String componentUuid
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "COMPONENT"."NAME" AS "name"
               , "MATCHING_PERCENTAGE" AS "confidence"
               , "DESCRIPTION" AS "desc"
               , "GROUP" AS "group"
               , "VERSION" AS "version"
               , "COMPONENT"."UUID" AS "componentUuid"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "COMPONENT" ON "FINDINGATTRIBUTION"."COMPONENT_ID" = "COMPONENT"."ID"
            INNER JOIN "ADVISORIES_VULNERABILITIES"
              ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "ADVISORIES_VULNERABILITIES"."VULNERABILITY_ID"
            INNER JOIN "ADVISORY" ON "ADVISORIES_VULNERABILITIES"."ADVISORY_ID" = "ADVISORY"."ID"
            WHERE "FINDINGATTRIBUTION"."PROJECT_ID" = :projectId
            AND "ADVISORY_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.ProjectAdvisoryFinding.class)
    List<AdvisoryDao.ProjectAdvisoryFinding> getFindingsByProjectAdvisory(@Bind long projectId, @Bind long advisoryId);

}
