package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.persistence.jdbi.mapping.NotificationComponentRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationProjectRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerabilityRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectNewVulnerableDependencyRowReducer;
import org.dependencytrack.persistence.jdbi.mapping.NotificationSubjectProjectAuditChangeRowMapper;
import org.dependencytrack.persistence.jdbi.mapping.NotificationVulnerabilityRowMapper;
import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMappers;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RegisterRowMappers({
        @RegisterRowMapper(NotificationComponentRowMapper.class),
        @RegisterRowMapper(NotificationProjectRowMapper.class),
        @RegisterRowMapper(NotificationVulnerabilityRowMapper.class)
})
public interface NotificationSubjectDao {

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
              "CALC_SEVERITY"(
                "V"."SEVERITY",
                "A"."SEVERITY",
                "V"."CVSSV3BASESCORE",
                "V"."CVSSV2BASESCORE"
              )                    AS "vulnSeverity",
              STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes",
              "vulnAliasesJson",
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
                ))) AS TEXT) AS "vulnAliasesJson"
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
              "C"."UUID" = (:componentUuid)::TEXT AND "V"."UUID" = ANY((:vulnUuids)::TEXT[])
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
              "CALC_SEVERITY"(
                "V"."SEVERITY",
                "A"."SEVERITY",
                "V"."CVSSV3BASESCORE",
                "V"."CVSSV2BASESCORE"
              )                                AS "vulnSeverity",
              STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes",
              "vulnAliasesJson"
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
                ))) AS TEXT) AS "vulnAliasesJson"
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
              "C"."UUID" = (:componentUuid)::TEXT
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
              "CALC_SEVERITY"(
                "V"."SEVERITY",
                "A"."SEVERITY",
                "V"."CVSSV3BASESCORE",
                "V"."CVSSV2BASESCORE"
              )                    AS "vulnSeverity",
              STRING_TO_ARRAY("V"."CWES", ',') AS "vulnCwes",
              "vulnAliasesJson",
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
                ))) AS TEXT) AS "vulnAliasesJson"
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
              "C"."UUID" = (:componentUuid)::TEXT AND "V"."UUID" = (:vulnUuid)::TEXT
            """)
    @RegisterRowMapper(NotificationSubjectProjectAuditChangeRowMapper.class)

    Optional<VulnerabilityAnalysisDecisionChangeSubject> getForProjectAuditChange(final UUID componentUuid, final UUID vulnUuid, AnalysisState analysisState, boolean isSuppressed);
}
