package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.CsafDocumentEntity;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

public interface AdvisoryDao {


    record AdvisoryRow(
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
            
            SELECT "NAME" AS "name"
                 , "PROJECT_ID" AS "projectId"
                 , "URL" AS "url"
                 , "CSAFDOCUMENT_ID" AS "documentId"
                 , COUNT("FINDINGATTRIBUTION"."ID") AS "findingsPerDoc"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
               ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "PROJECT_ID" = :projectId
            GROUP BY "CSAFDOCUMENT_ID", "NAME", "URL", "PROJECT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoryRow.class)
    List<AdvisoryDao.AdvisoryRow> getAdvisoriesByProject(@Bind long projectId, @Bind boolean includeSuppressed);

    record AdvisoryResult(
            CsafDocumentEntity entity,
            List<ProjectRow> affectedProjects,
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
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            INNER JOIN "PROJECT" ON "PROJECT_ID" = "PROJECT"."ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.ProjectRow.class)
    List<ProjectRow> getProjectsByAdvisory(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT DISTINCT "VULNERABILITY"."ID" AS "id",
            "SOURCE" AS "source",
            "VULNID" AS "vulnId"
            
            FROM "CSAFMAPPING"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            INNER JOIN "VULNERABILITY" ON "CSAFMAPPING"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.VulnerabilityRow.class)
    List<VulnerabilityRow> getVulnerabilitiesByAdvisory(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID") AS "findingsWithAnalysis"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            INNER JOIN "ANALYSIS" ON
            "FINDINGATTRIBUTION"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            GROUP BY "CSAFDOCUMENT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    long getAmountFindingsMarked(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID") AS "findingsWithAnalysis"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            GROUP BY "CSAFDOCUMENT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    long getAmountFindingsTotal(long advisoryId);

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

            SELECT "CSAFDOCUMENTENTITY"."NAME" as "name",
            COUNT("PROJECT_ID") AS "affectedComponents",
            COUNT(DISTINCT "PROJECT_ID") AS "affectedProjects",
            "URL" AS "url",
            "CSAFDOCUMENTENTITY"."ID" AS "documentId"
            FROM "CSAFDOCUMENTENTITY"
            LEFT JOIN "CSAFMAPPING" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            LEFT JOIN "FINDINGATTRIBUTION" ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            GROUP BY "CSAFDOCUMENTENTITY"."ID","CSAFDOCUMENTENTITY"."NAME","URL"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoriesPortfolioRow.class)
    List<AdvisoriesPortfolioRow> getAllAdvisories();


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
            INNER JOIN "CSAFMAPPING"
              ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "FINDINGATTRIBUTION"."PROJECT_ID" = :projectId
            AND "CSAFDOCUMENT_ID" = :advisoryId
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.ProjectAdvisoryFinding.class)
    List<AdvisoryDao.ProjectAdvisoryFinding> getFindingsByProjectAdvisory(@Bind long projectId, @Bind long advisoryId);


}
