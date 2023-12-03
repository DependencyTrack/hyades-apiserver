package org.dependencytrack.notification.persistence;

import org.dependencytrack.proto.notification.v1.NewVulnerabilitySubject;
import org.dependencytrack.proto.notification.v1.NewVulnerableDependencySubject;
import org.dependencytrack.proto.notification.v1.Notification;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisCompleteSubject;
import org.jdbi.v3.sqlobject.config.RegisterCollector;
import org.jdbi.v3.sqlobject.config.RegisterRowMapper;
import org.jdbi.v3.sqlobject.config.RegisterRowMappers;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.UseRowReducer;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Data Access Object for retrieving {@link Notification} subject data.
 */
public interface NotificationSubjectDao {

    @SqlQuery("""
            SELECT
              "C"."UUID"                        AS "componentUuid",
              "C"."GROUP"                       AS "componentGroup",
              "C"."NAME"                        AS "componentName",
              "C"."VERSION"                     AS "componentVersion",
              "C"."PURL"                        AS "componentPurl",
              "C"."MD5"                         AS "componentMd5",
              "C"."SHA1"                        AS "componentSha1",
              "C"."SHA_256"                     AS "componentSha256",
              "C"."SHA_512"                     AS "componentSha512",
              "P"."UUID"                        AS "projectUuid",
              "P"."NAME"                        AS "projectName",
              "P"."VERSION"                     AS "projectVersion",
              "P"."DESCRIPTION"                 AS "projectDescription",
              "P"."PURL"                        AS "projectPurl",
              (SELECT
                 STRING_AGG("T"."NAME", ',')
               FROM
                 "TAG" AS "T"
               INNER JOIN
                 "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
               WHERE
                 "PT"."PROJECT_ID" = "P"."ID"
              )                                 AS "projectTags",
              "V"."UUID"                        AS "vulnUuid",
              "V"."VULNID"                      AS "vulnId",
              "V"."SOURCE"                      AS "vulnSource",
              "V"."TITLE"                       AS "vulnTitle",
              "V"."SUBTITLE"                    AS "vulnSubTitle",
              "V"."DESCRIPTION"                 AS "vulnDescription",
              "V"."RECOMMENDATION"              AS "vulnRecommendation",
              "V"."CVSSV2BASESCORE"             AS "vulnCvssV2BaseScore",
              "V"."CVSSV3BASESCORE"             AS "vulnCvssV3BaseScore",
              "V"."OWASPRRBUSINESSIMPACTSCORE"  AS "vulnOwaspRrBusinessImpactScore",
              "V"."OWASPRRLIKELIHOODSCORE"      AS "vulnOwaspRrLikelihoodScore",
              "V"."OWASPRRTECHNICALIMPACTSCORE" AS "vulnOwaspRrTechnicalImpactScore",
              "V"."SEVERITY"                    AS "vulnSeverity",
              "V"."CWES"                        AS "vulnCwes",
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
              "C"."UUID" = :componentUuid AND "V"."UUID" = ANY(:vulnUuids)
              AND ("A"."SUPPRESSED" IS NULL OR NOT "A"."SUPPRESSED")
            """)
    @RegisterRowMappers({
            @RegisterRowMapper(ComponentRowMapper.class),
            @RegisterRowMapper(ProjectRowMapper.class),
            @RegisterRowMapper(VulnerabilityRowMapper.class),
            @RegisterRowMapper(NewVulnerabilitySubjectRowMapper.class)
    })
    List<NewVulnerabilitySubject> getForNewVulnerabilities(@Bind("componentUuid") final String componentUuid, @Bind("vulnUuids") final Collection<String> vulnUuids);

    @SqlQuery("""
            SELECT
              "C"."UUID"                        AS "componentUuid",
              "C"."GROUP"                       AS "componentGroup",
              "C"."NAME"                        AS "componentName",
              "C"."VERSION"                     AS "componentVersion",
              "C"."PURL"                        AS "componentPurl",
              "C"."MD5"                         AS "componentMd5",
              "C"."SHA1"                        AS "componentSha1",
              "C"."SHA_256"                     AS "componentSha256",
              "C"."SHA_512"                     AS "componentSha512",
              "P"."UUID"                        AS "projectUuid",
              "P"."NAME"                        AS "projectName",
              "P"."VERSION"                     AS "projectVersion",
              "P"."DESCRIPTION"                 AS "projectDescription",
              "P"."PURL"                        AS "projectPurl",
              (SELECT
                 STRING_AGG("T"."NAME", ',')
               FROM
                 "TAG" AS "T"
               INNER JOIN
                 "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
               WHERE
                 "PT"."PROJECT_ID" = "P"."ID"
              )                                 AS "projectTags",
              "V"."UUID"                        AS "vulnUuid",
              "V"."VULNID"                      AS "vulnId",
              "V"."SOURCE"                      AS "vulnSource",
              "V"."TITLE"                       AS "vulnTitle",
              "V"."SUBTITLE"                    AS "vulnSubTitle",
              "V"."DESCRIPTION"                 AS "vulnDescription",
              "V"."RECOMMENDATION"              AS "vulnRecommendation",
              "V"."CVSSV2BASESCORE"             AS "vulnCvssV2BaseScore",
              "V"."CVSSV3BASESCORE"             AS "vulnCvssV3BaseScore",
              "V"."OWASPRRBUSINESSIMPACTSCORE"  AS "vulnOwaspRrBusinessImpactScore",
              "V"."OWASPRRLIKELIHOODSCORE"      AS "vulnOwaspRrLikelihoodScore",
              "V"."OWASPRRTECHNICALIMPACTSCORE" AS "vulnOwaspRrTechnicalImpactScore",
              "V"."SEVERITY"                    AS "vulnSeverity",
              "V"."CWES"                        AS "vulnCwes"
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
    @RegisterRowMappers({
            @RegisterRowMapper(ComponentRowMapper.class),
            @RegisterRowMapper(ProjectRowMapper.class),
            @RegisterRowMapper(VulnerabilityRowMapper.class)
    })
    @UseRowReducer(NewVulnerableDependencySubjectRowReducer.class)
    Optional<NewVulnerableDependencySubject> getForNewVulnerableDependency(@Bind("componentUuid") final String componentUuid);

    @SqlQuery("""
            SELECT
              "C"."UUID"                        AS "componentUuid",
              "C"."GROUP"                       AS "componentGroup",
              "C"."NAME"                        AS "componentName",
              "C"."VERSION"                     AS "componentVersion",
              "C"."PURL"                        AS "componentPurl",
              "C"."MD5"                         AS "componentMd5",
              "C"."SHA1"                        AS "componentSha1",
              "C"."SHA_256"                     AS "componentSha256",
              "C"."SHA_512"                     AS "componentSha512",
              "P"."UUID"                        AS "projectUuid",
              "P"."NAME"                        AS "projectName",
              "P"."VERSION"                     AS "projectVersion",
              "P"."DESCRIPTION"                 AS "projectDescription",
              "P"."PURL"                        AS "projectPurl",
              (SELECT
                 STRING_AGG("T"."NAME", ',')
               FROM
                 "TAG" AS "T"
               INNER JOIN
                 "PROJECTS_TAGS" AS "PT" ON "PT"."TAG_ID" = "T"."ID"
               WHERE
                 "PT"."PROJECT_ID" = "P"."ID"
              )                                 AS "projectTags",
              "V"."UUID"                        AS "vulnUuid",
              "V"."VULNID"                      AS "vulnId",
              "V"."SOURCE"                      AS "vulnSource",
              "V"."TITLE"                       AS "vulnTitle",
              "V"."SUBTITLE"                    AS "vulnSubTitle",
              "V"."DESCRIPTION"                 AS "vulnDescription",
              "V"."RECOMMENDATION"              AS "vulnRecommendation",
              "V"."CVSSV2BASESCORE"             AS "vulnCvssV2BaseScore",
              "V"."CVSSV3BASESCORE"             AS "vulnCvssV3BaseScore",
              "V"."OWASPRRBUSINESSIMPACTSCORE"  AS "vulnOwaspRrBusinessImpactScore",
              "V"."OWASPRRLIKELIHOODSCORE"      AS "vulnOwaspRrLikelihoodScore",
              "V"."OWASPRRTECHNICALIMPACTSCORE" AS "vulnOwaspRrTechnicalImpactScore",
              "V"."SEVERITY"                    AS "vulnSeverity",
              "V"."CWES"                        AS "vulnCwes",
              "VS"."TOKEN"                      AS "vulnScanToken",
              "VS"."STATUS"                     AS "vulnScanStatus"
            FROM
              "VULNERABILITYSCAN" AS "VS"
            INNER JOIN
              "PROJECT" AS "P" ON "P"."UUID" = "VS"."TARGET_IDENTIFIER"
            INNER JOIN
             "COMPONENT" AS "C" ON "C"."PROJECT_ID" = "P"."ID"
            INNER JOIN
              "COMPONENTS_VULNERABILITIES" AS "CV" ON "CV"."COMPONENT_ID" = "C"."ID"
            INNER JOIN
              "VULNERABILITY" AS "V" ON "V"."ID" = "CV"."VULNERABILITY_ID"
            LEFT JOIN
              "ANALYSIS" AS "A" ON "A"."COMPONENT_ID" = "C"."ID" AND "A"."VULNERABILITY_ID" = "V"."ID"
            WHERE
              "VS"."TOKEN" = :scanToken
              AND ("A"."SUPPRESSED" IS NULL OR NOT "A"."SUPPRESSED")
            """)
    @RegisterRowMappers({
            @RegisterRowMapper(ComponentRowMapper.class),
            @RegisterRowMapper(ProjectRowMapper.class),
            @RegisterRowMapper(VulnerabilityRowMapper.class)
    })
    @RegisterCollector(ProjectVulnAnalysisCompleteSubjectCollector.class)
    Optional<ProjectVulnAnalysisCompleteSubject> getForProjectVulnAnalysisComplete(final String scanToken);

    @SqlQuery("""
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
              "PV"."ID" = :violationId AND (
                ("VA"."SUPPRESSED" IS NULL OR NOT "VA"."SUPPRESSED")
                OR
                "VA"."STATE" != 'APPROVED'
              )
            """)
    @RegisterRowMappers({
            @RegisterRowMapper(ComponentRowMapper.class),
            @RegisterRowMapper(ProjectRowMapper.class),
            @RegisterRowMapper(PolicyRowMapper.class),
            @RegisterRowMapper(PolicyConditionRowMapper.class),
            @RegisterRowMapper(PolicyViolationRowMapper.class),
            @RegisterRowMapper(PolicyViolationSubjectRowMapper.class)
    })
    Optional<PolicyViolationSubject> getForPolicyViolation(final long violationId);

}
