package org.dependencytrack.persistence.jdbi;

import alpine.persistence.PaginatedResult;
import alpine.persistence.Pagination;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.mapping.FindingPaginatedResultRowReducer;
import org.dependencytrack.persistence.jdbi.mapping.FindingRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.Define;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;

@RegisterRowMapper(FindingRowMapper.class)
public interface FindingDao {

    @SqlQuery("""
            SELECT
              "P"."UUID"                        AS "projectUuid",
              "C"."UUID"                        AS "componentUuid",
              "C"."GROUP"                       AS "componentGroup",
              "C"."NAME"                        AS "componentName",
              "C"."VERSION"                     AS "componentVersion",
              "C"."CPE"                         AS "componentCpe",
              "C"."PURL"                        AS "componentPurl",
              "RMC"."LATEST_VERSION"            AS "componentLatestVersion",
              "V"."UUID"                        AS "vulnUuid",
              "V"."VULNID"                      AS "vulnId",
              "V"."SOURCE"                      AS "vulnSource",
              "V"."TITLE"                       AS "vulnTitle",
              "V"."SUBTITLE"                    AS "vulnSubTitle",
              "V"."DESCRIPTION"                 AS "vulnDescription",
              "V"."RECOMMENDATION"              AS "vulnRecommendation",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV2SCORE"
                ELSE "V"."CVSSV2BASESCORE"
              END                               AS "vulnCvssV2BaseScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."CVSSV3SCORE"
                ELSE "V"."CVSSV3BASESCORE"
              END                               AS "vulnCvssV3BaseScore",
              -- TODO: Analysis only has a single score, but OWASP RR defines multiple.
              --  How to handle this?
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRBUSINESSIMPACTSCORE"
              END                               AS "vulnOwaspRrBusinessImpactScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRLIKELIHOODSCORE"
              END                               AS "vulnOwaspRrLikelihoodScore",
              CASE
                WHEN "A"."SEVERITY" IS NOT NULL THEN "A"."OWASPSCORE"
                ELSE "V"."OWASPRRTECHNICALIMPACTSCORE"
              END                               AS "vulnOwaspRrTechnicalImpactScore",
              "CALC_SEVERITY"(
                "V"."SEVERITY",
                "A"."SEVERITY",
                "V"."CVSSV3BASESCORE",
                "V"."CVSSV2BASESCORE"
              )                                 AS "vulnSeverity",
              "V"."EPSSSCORE"                   AS "vulnEpssScore",
              "V"."EPSSPERCENTILE"              AS "vulnEpssPercentile",
              STRING_TO_ARRAY("V"."CWES", ',')  AS "vulnCwes",
              "FA"."ANALYZERIDENTITY"           AS "analyzerIdentity",
              "FA"."ATTRIBUTED_ON"              AS "attributedOn",
              "FA"."ALT_ID"                     AS "alternateIdentifier",
              "FA"."REFERENCE_URL"              AS "referenceUrl",
              "A"."STATE"                       AS "analysisState",
              "A"."SUPPRESSED"                  AS "isSuppressed",
              COUNT(*) OVER()                   AS "totalCount"
            FROM
              "PROJECT" AS "P"
            INNER JOIN
              "COMPONENT" AS "C" ON "C"."PROJECT_ID" = "P"."ID"
            INNER JOIN
              "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."COMPONENT_ID" = "C"."ID"
            INNER JOIN
              "VULNERABILITY" AS "V" ON "V"."ID" = "CV"."VULNERABILITY_ID"
            INNER JOIN
              "FINDINGATTRIBUTION" AS "FA" ON "FA"."COMPONENT_ID" = "C"."ID" AND "FA"."VULNERABILITY_ID" = "V"."ID"
            LEFT JOIN
              "ANALYSIS" AS "A" ON "A"."COMPONENT_ID" = "C"."ID" AND "A"."VULNERABILITY_ID" = "V"."ID"
            LEFT JOIN
              -- TODO: Find a better performing way to join.
              --  Perhaps write a SQL function that can parse type, namespace, and name from "C"."PURL"
              --  and perform the join on "RMC"."NAMESPACE" and "RMC"."NAME" instead.
              "REPOSITORY_META_COMPONENT" AS "RMC"
                ON "C"."PURL" LIKE (
                  'pkg:' || LOWER("RMC"."REPOSITORY_TYPE")
                    || CASE WHEN "RMC"."NAMESPACE" IS NOT NULL THEN '/' || "RMC"."NAMESPACE" ELSE '' END
                    || '/' || "RMC"."NAME" || '@%'
                )
            LEFT JOIN LATERAL (
              SELECT
                CAST(JSONB_AGG(DISTINCT JSONB_STRIP_NULLS(JSONB_BUILD_OBJECT(
                  'cveId',      "VA"."CVE_ID",
                  'ghsaId',     "VA"."GHSA_ID",
                  'gsdId',      "VA"."GSD_ID",
                  'internalId', "VA"."INTERNAL_ID",
                  'osvId',      "VA"."OSV_ID",
                  'sonatypeId', "VA"."SONATYPE_ID",
                  'snykId',     "VA"."SNYK_ID",
                  'vulnDbId',   "VA"."VULNDB_ID"
                ))) AS TEXT) AS "vulnAliases"
              FROM
                "VULNERABILITYALIAS" AS "VA"
              WHERE
                ("V"."SOURCE" = 'NVD' AND "VA"."CVE_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'GITHUB' AND "VA"."GHSA_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'GSD' AND "VA"."GSD_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'INTERNAL' AND "VA"."INTERNAL_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'OSV' AND "VA"."OSV_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'SONATYPE' AND "VA"."SONATYPE_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'SNYK' AND "VA"."SNYK_ID" = "V"."VULNID")
                  OR ("V"."SOURCE" = 'VULNDB' AND "VA"."VULNDB_ID" = "V"."VULNID")
            ) AS "vulnAliases" ON TRUE
            WHERE
              "P"."ID" = :projectId
              AND ((:sourceFilter)::TEXT IS NULL OR ("V"."SOURCE" = :sourceFilter))
              AND (:includeSuppressed OR "A"."SUPPRESSED" IS NULL OR NOT "A"."SUPPRESSED")
            <#if pagination.isPaginated()>
              OFFSET ${pagination.offset} FETCH NEXT ${pagination.limit} ROWS ONLY
            </#if>
            """)
    @UseRowReducer(FindingPaginatedResultRowReducer.class)
    PaginatedResult getPageForProject(@Define final Pagination pagination, @Bind final long projectId,
                                      @Bind final Vulnerability.Source sourceFilter, @Bind final boolean includeSuppressed);

}
