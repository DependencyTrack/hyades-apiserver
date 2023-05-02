-- Calculate the severity of a vulnerability based on its CVSSv2 base score.
CREATE OR REPLACE FUNCTION "CVSSV2_TO_SEVERITY"(
    "base_score" NUMERIC
) RETURNS VARCHAR
    LANGUAGE "plpgsql"
AS
$$
BEGIN
    RETURN CASE
               WHEN "base_score" >= 7 THEN 'HIGH'
               WHEN "base_score" >= 4 THEN 'MEDIUM'
               WHEN "base_score" > 0 THEN 'LOW'
               ELSE 'UNASSIGNED'
        END;
END;
$$;

-- Calculate the severity of a vulnerability based on its CVSSv3 base score.
CREATE OR REPLACE FUNCTION "CVSSV3_TO_SEVERITY"(
    "base_score" NUMERIC
) RETURNS VARCHAR
    LANGUAGE "plpgsql"
AS
$$
BEGIN
    RETURN CASE
               WHEN "base_score" >= 9 THEN 'CRITICAL'
               WHEN "base_score" >= 7 THEN 'HIGH'
               WHEN "base_score" >= 4 THEN 'MEDIUM'
               WHEN "base_score" > 0 THEN 'LOW'
               ELSE 'UNASSIGNED'
        END;
END;
$$;

-- Calculate the severity of a vulnerability based on:
--   * a pre-set severity
--   * a CVSSv3 base score
--   * a CVSSv2 base score
-- The behavior of this function is identical to Vulnerability#getSeverity
-- in the API server Java code base.
-- https://github.com/DependencyTrack/dependency-track/blob/1976be1f5cc9d027900f09aed9d1539595aeda3a/src/main/java/org/dependencytrack/model/Vulnerability.java#L338-L340
CREATE OR REPLACE FUNCTION "CALC_SEVERITY"(
    "severity" VARCHAR,
    "cvssv3_base_score" NUMERIC,
    "cvssv2_base_score" NUMERIC
) RETURNS VARCHAR
    LANGUAGE "plpgsql"
AS
$$
BEGIN
    IF "cvssv3_base_score" IS NOT NULL THEN
        RETURN "CVSSV3_TO_SEVERITY"("cvssv3_base_score");
    ELSEIF "cvssv2_base_score" IS NOT NULL THEN
        RETURN "CVSSV2_TO_SEVERITY"("cvssv2_base_score");
    ELSEIF "severity" IS NOT NULL THEN
        RETURN "severity";
    ELSE
        RETURN 'UNASSIGNED';
    END IF;
END;
$$;

-- Calculate the inherited risk score of a component, based on the number
-- of vulnerabilities per severity.
-- The behavior of this function is identical to Metrics#inheritedRiskScore
-- in the API server Java code base.
-- https://github.com/DependencyTrack/dependency-track/blob/1976be1f5cc9d027900f09aed9d1539595aeda3a/src/main/java/org/dependencytrack/metrics/Metrics.java#L31-L33
CREATE OR REPLACE FUNCTION "CALC_RISK_SCORE"(
    "critical" INT,
    "high" INT,
    "medium" INT,
    "low" INT,
    "unassigned" INT
) RETURNS NUMERIC
    LANGUAGE "plpgsql"
AS
$$
BEGIN
    RETURN ("critical" * 10) + ("high" * 5) + ("medium" * 3) + ("low" * 1) + ("unassigned" * 5);
END;
$$;

CREATE OR REPLACE PROCEDURE "UPDATE_COMPONENT_METRICS"(
    "component_uuid" VARCHAR
)
    LANGUAGE "plpgsql"
AS
$$
DECLARE
    "v_component"                               RECORD; -- The component to update metrics for
    "v_vulnerability"                           RECORD; -- Loop variable for iterating over vulnerabilities the component is affected by
    "v_severity"                                VARCHAR; -- Loop variable for the current vulnerability's severity
    "v_policy_violation"                        RECORD; -- Loop variable for iterating over policy violations assigned to the component
    "v_vulnerabilities"                         INT     := 0; -- Total number of vulnerabilities
    "v_critical"                                INT     := 0; -- Number of vulnerabilities with critical severity
    "v_high"                                    INT     := 0; -- Number of vulnerabilities with high severity
    "v_medium"                                  INT     := 0; -- Number of vulnerabilities with medium severity
    "v_low"                                     INT     := 0; -- Number of vulnerabilities with low severity
    "v_unassigned"                              INT     := 0; -- Number of vulnerabilities with unassigned severity
    "v_risk_score"                              NUMERIC := 0; -- Inherited risk score
    "v_findings_total"                          INT     := 0; -- Total number of findings
    "v_findings_audited"                        INT     := 0; -- Number of audited findings
    "v_findings_unaudited"                      INT     := 0; -- Number of unaudited findings
    "v_findings_suppressed"                     INT     := 0; -- Number of suppressed findings
    "v_policy_violations_total"                 INT     := 0; -- Total number of policy violations
    "v_policy_violations_fail"                  INT     := 0; -- Number of policy violations with level fail
    "v_policy_violations_warn"                  INT     := 0; -- Number of policy violations with level warn
    "v_policy_violations_info"                  INT     := 0; -- Number of policy violations with level info
    "v_policy_violations_audited"               INT     := 0; -- Number of audited policy violations
    "v_policy_violations_unaudited"             INT     := 0; -- Number of unaudited policy violations
    "v_policy_violations_license_total"         INT     := 0; -- Total number of policy violations of type license
    "v_policy_violations_license_audited"       INT     := 0; -- Number of audited policy violations of type license
    "v_policy_violations_license_unaudited"     INT     := 0; -- Number of unaudited policy violations of type license
    "v_policy_violations_operational_total"     INT     := 0; -- Total number of policy violations of type operational
    "v_policy_violations_operational_audited"   INT     := 0; -- Number of audited policy violations of type operational
    "v_policy_violations_operational_unaudited" INT     := 0; -- Number of unaudited policy violations of type operational
    "v_policy_violations_security_total"        INT     := 0; -- Total number of policy violations of type security
    "v_policy_violations_security_audited"      INT     := 0; -- Number of audited policy violations of type security
    "v_policy_violations_security_unaudited"    INT     := 0; -- Number of unaudited policy violations of type security
    "v_existing_id"                             BIGINT; -- ID of the existing row that matches the data point calculated in this procedure
BEGIN
    SELECT "ID", "PROJECT_ID" INTO "v_component" FROM "COMPONENT" WHERE "UUID" = "component_uuid";
    IF "v_component" IS NULL THEN
        RAISE EXCEPTION 'Component with UUID % does not exist', "component_uuid";
    END IF;

    FOR "v_vulnerability" IN SELECT "VULNID", "SOURCE", "SEVERITY", "CVSSV2BASESCORE", "CVSSV3BASESCORE"
                             FROM "VULNERABILITY" AS "V"
                                      INNER JOIN "COMPONENTS_VULNERABILITIES" AS "CV"
                                                 ON "CV"."COMPONENT_ID" = "v_component"."ID"
                                                     AND "CV"."VULNERABILITY_ID" = "V"."ID"
                             WHERE NOT EXISTS(SELECT 1
                                              FROM "ANALYSIS" AS "A"
                                              WHERE "A"."COMPONENT_ID" = "v_component"."ID"
                                                AND "A"."VULNERABILITY_ID" = "CV"."VULNERABILITY_ID"
                                                AND "A"."SUPPRESSED" = TRUE)
        LOOP
            -- TODO: Check aliases

            "v_vulnerabilities" := "v_vulnerabilities" + 1;

            SELECT "CALC_SEVERITY"(
                           "v_vulnerability"."SEVERITY",
                           "v_vulnerability"."CVSSV3BASESCORE",
                           "v_vulnerability"."CVSSV2BASESCORE")
            INTO "v_severity";

            IF "v_severity" = 'CRITICAL' THEN
                "v_critical" := "v_critical" + 1;
            ELSEIF "v_severity" = 'HIGH' THEN
                "v_high" := "v_high" + 1;
            ELSEIF "v_severity" = 'MEDIUM' THEN
                "v_medium" := "v_medium" + 1;
            ELSEIF "v_severity" = 'LOW' THEN
                "v_low" := "v_low" + 1;
            ELSE
                "v_unassigned" := "v_unassigned" + 1;
            END IF;

        END LOOP;

    "v_risk_score" = "CALC_RISK_SCORE"("v_critical", "v_high", "v_medium", "v_low", "v_unassigned");

    SELECT COUNT(*)
    FROM "ANALYSIS" AS "A"
    WHERE "A"."COMPONENT_ID" = "v_component"."ID"
      AND "A"."SUPPRESSED" = FALSE
      AND "A"."STATE" != 'NOT_SET'
      AND "A"."STATE" != 'IN_TRIAGE'
    INTO "v_findings_audited";

    "v_findings_total" = "v_vulnerabilities";
    "v_findings_unaudited" = "v_findings_total" - "v_findings_audited";

    SELECT COUNT(*)
    FROM "ANALYSIS" AS "A"
    WHERE "A"."COMPONENT_ID" = "v_component"."ID"
      AND "A"."SUPPRESSED" = TRUE
    INTO "v_findings_suppressed";

    FOR "v_policy_violation" IN SELECT "PV"."TYPE", "P"."VIOLATIONSTATE"
                                FROM "POLICYVIOLATION" AS "PV"
                                         INNER JOIN "POLICYCONDITION" AS "PC" ON "PV"."POLICYCONDITION_ID" = "PC"."ID"
                                         INNER JOIN "POLICY" AS "P" ON "PC"."POLICY_ID" = "P"."ID"
                                         LEFT JOIN "VIOLATIONANALYSIS" AS "VA"
                                                   ON "VA"."COMPONENT_ID" = "v_component"."ID" AND
                                                      "VA"."POLICYVIOLATION_ID" = "PV"."ID"
                                WHERE "PV"."COMPONENT_ID" = "v_component"."ID"
                                  AND ("VA" IS NULL OR "VA"."SUPPRESSED" = FALSE)
        LOOP
            "v_policy_violations_total" := "v_policy_violations_total" + 1;

            IF "v_policy_violation"."TYPE" = 'LICENSE' THEN
                "v_policy_violations_license_total" := "v_policy_violations_license_total" + 1;
            ELSEIF "v_policy_violation"."TYPE" = 'OPERATIONAL' THEN
                "v_policy_violations_operational_total" := "v_policy_violations_operational_total" + 1;
            ELSEIF "v_policy_violation"."TYPE" = 'SECURITY' THEN
                "v_policy_violations_security_total" := "v_policy_violations_security_total" + 1;
            ELSE
                RAISE EXCEPTION 'Encountered invalid policy violation type %', "v_policy_violation"."TYPE";
            END IF;

            IF "v_policy_violation"."VIOLATIONSTATE" = 'FAIL' THEN
                "v_policy_violations_fail" := "v_policy_violations_fail" + 1;
            ELSEIF "v_policy_violation"."VIOLATIONSTATE" = 'WARN' THEN
                "v_policy_violations_warn" := "v_policy_violations_warn" + 1;
            ELSEIF "v_policy_violation"."VIOLATIONSTATE" = 'INFO' THEN
                "v_policy_violations_info" := "v_policy_violations_info" + 1;
            ELSE
                RAISE EXCEPTION 'Encountered invalid violation state %', "v_policy_violation"."VIOLATIONSTATE";
            end if;
        END LOOP;

    SELECT COUNT(*)
    FROM "VIOLATIONANALYSIS" AS "VA"
             INNER JOIN "POLICYVIOLATION" AS "PV" ON "PV"."ID" = "VA"."POLICYVIOLATION_ID"
    WHERE "VA"."COMPONENT_ID" = "v_component"."ID"
      AND "PV"."TYPE" = 'LICENSE'
      AND "VA"."SUPPRESSED" = FALSE
      AND "VA"."STATE" != 'NOT_SET'
    INTO "v_policy_violations_license_audited";
    "v_policy_violations_license_unaudited" =
                "v_policy_violations_license_total" - "v_policy_violations_license_audited";

    SELECT COUNT(*)
    FROM "VIOLATIONANALYSIS" AS "VA"
             INNER JOIN "POLICYVIOLATION" AS "PV" ON "PV"."ID" = "VA"."POLICYVIOLATION_ID"
    WHERE "VA"."COMPONENT_ID" = "v_component"."ID"
      AND "PV"."TYPE" = 'OPERATIONAL'
      AND "VA"."SUPPRESSED" = FALSE
      AND "VA"."STATE" != 'NOT_SET'
    INTO "v_policy_violations_operational_audited";
    "v_policy_violations_operational_unaudited" =
                "v_policy_violations_operational_total" - "v_policy_violations_operational_audited";

    SELECT COUNT(*)
    FROM "VIOLATIONANALYSIS" AS "VA"
             INNER JOIN "POLICYVIOLATION" AS "PV" ON "PV"."ID" = "VA"."POLICYVIOLATION_ID"
    WHERE "VA"."COMPONENT_ID" = "v_component"."ID"
      AND "PV"."TYPE" = 'SECURITY'
      AND "VA"."SUPPRESSED" = FALSE
      AND "VA"."STATE" != 'NOT_SET'
    INTO "v_policy_violations_security_audited";
    "v_policy_violations_security_unaudited" =
                "v_policy_violations_security_total" - "v_policy_violations_security_audited";

    "v_policy_violations_audited" = "v_policy_violations_license_audited"
        + "v_policy_violations_operational_audited"
        + "v_policy_violations_security_audited";
    "v_policy_violations_unaudited" = "v_policy_violations_total" - "v_policy_violations_audited";

    SELECT DISTINCT ON ("ID") "ID"
    FROM "DEPENDENCYMETRICS"
    WHERE "COMPONENT_ID" = "v_component"."ID"
      AND "VULNERABILITIES" = "v_vulnerabilities"
      AND "CRITICAL" = "v_critical"
      AND "HIGH" = "v_high"
      AND "MEDIUM" = "v_medium"
      AND "LOW" = "v_low"
      AND "UNASSIGNED_SEVERITY" = "v_unassigned"
      AND "RISKSCORE" = "v_risk_score"
      AND "FINDINGS_TOTAL" = "v_findings_total"
      AND "FINDINGS_AUDITED" = "v_findings_audited"
      AND "FINDINGS_UNAUDITED" = "v_findings_unaudited"
      AND "SUPPRESSED" = "v_findings_suppressed"
      AND "POLICYVIOLATIONS_TOTAL" = "v_policy_violations_total"
      AND "POLICYVIOLATIONS_FAIL" = "v_policy_violations_fail"
      AND "POLICYVIOLATIONS_WARN" = "v_policy_violations_warn"
      AND "POLICYVIOLATIONS_INFO" = "v_policy_violations_info"
      AND "POLICYVIOLATIONS_AUDITED" = "v_policy_violations_audited"
      AND "POLICYVIOLATIONS_UNAUDITED" = "v_policy_violations_unaudited"
      AND "POLICYVIOLATIONS_LICENSE_TOTAL" = "v_policy_violations_license_total"
      AND "POLICYVIOLATIONS_LICENSE_AUDITED" = "v_policy_violations_license_audited"
      AND "POLICYVIOLATIONS_LICENSE_UNAUDITED" = "v_policy_violations_license_unaudited"
      AND "POLICYVIOLATIONS_OPERATIONAL_TOTAL" = "v_policy_violations_operational_total"
      AND "POLICYVIOLATIONS_OPERATIONAL_AUDITED" = "v_policy_violations_operational_audited"
      AND "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" = "v_policy_violations_operational_unaudited"
      AND "POLICYVIOLATIONS_SECURITY_TOTAL" = "v_policy_violations_security_total"
      AND "POLICYVIOLATIONS_SECURITY_AUDITED" = "v_policy_violations_security_audited"
      AND "POLICYVIOLATIONS_SECURITY_UNAUDITED" = "v_policy_violations_security_unaudited"
    ORDER BY "ID", "LAST_OCCURRENCE" DESC
    LIMIT 1
    INTO "v_existing_id";

    IF "v_existing_id" IS NOT NULL THEN
        UPDATE "DEPENDENCYMETRICS" SET "LAST_OCCURRENCE" = NOW() WHERE "ID" = "v_existing_id";
    ELSE
        INSERT INTO "DEPENDENCYMETRICS" ("COMPONENT_ID",
                                         "PROJECT_ID",
                                         "VULNERABILITIES",
                                         "CRITICAL",
                                         "HIGH",
                                         "MEDIUM",
                                         "LOW",
                                         "UNASSIGNED_SEVERITY",
                                         "RISKSCORE",
                                         "FINDINGS_TOTAL",
                                         "FINDINGS_AUDITED",
                                         "FINDINGS_UNAUDITED",
                                         "SUPPRESSED",
                                         "POLICYVIOLATIONS_TOTAL",
                                         "POLICYVIOLATIONS_FAIL",
                                         "POLICYVIOLATIONS_WARN",
                                         "POLICYVIOLATIONS_INFO",
                                         "POLICYVIOLATIONS_AUDITED",
                                         "POLICYVIOLATIONS_UNAUDITED",
                                         "POLICYVIOLATIONS_LICENSE_TOTAL",
                                         "POLICYVIOLATIONS_LICENSE_AUDITED",
                                         "POLICYVIOLATIONS_LICENSE_UNAUDITED",
                                         "POLICYVIOLATIONS_OPERATIONAL_TOTAL",
                                         "POLICYVIOLATIONS_OPERATIONAL_AUDITED",
                                         "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
                                         "POLICYVIOLATIONS_SECURITY_TOTAL",
                                         "POLICYVIOLATIONS_SECURITY_AUDITED",
                                         "POLICYVIOLATIONS_SECURITY_UNAUDITED",
                                         "FIRST_OCCURRENCE",
                                         "LAST_OCCURRENCE")
        VALUES ("v_component"."ID",
                "v_component"."PROJECT_ID",
                "v_vulnerabilities",
                "v_critical",
                "v_high",
                "v_medium",
                "v_low",
                "v_unassigned",
                "v_risk_score",
                "v_findings_total",
                "v_findings_audited",
                "v_findings_unaudited",
                "v_findings_suppressed",
                "v_policy_violations_total",
                "v_policy_violations_fail",
                "v_policy_violations_warn",
                "v_policy_violations_info",
                "v_policy_violations_audited",
                "v_policy_violations_unaudited",
                "v_policy_violations_license_total",
                "v_policy_violations_license_audited",
                "v_policy_violations_license_unaudited",
                "v_policy_violations_operational_total",
                "v_policy_violations_operational_audited",
                "v_policy_violations_operational_unaudited",
                "v_policy_violations_security_total",
                "v_policy_violations_security_audited",
                "v_policy_violations_security_unaudited",
                NOW(),
                NOW());

        UPDATE "COMPONENT" SET "LAST_RISKSCORE" = "v_risk_score" WHERE "ID" = "v_component"."ID";
    END IF;
END;
$$;

CREATE OR REPLACE PROCEDURE "UPDATE_PROJECT_METRICS"(
    "project_uuid" VARCHAR(36)
)
    LANGUAGE "plpgsql"
AS
$$
DECLARE
    "v_project_id"                              BIGINT;
    "v_components"                              INT     := 0; -- Total number of components in the project
    "v_vulnerable_components"                   INT     := 0; -- Number of vulnerable components in the project
    "v_vulnerabilities"                         INT     := 0; -- Total number of vulnerabilities
    "v_critical"                                INT     := 0; -- Number of vulnerabilities with critical severity
    "v_high"                                    INT     := 0; -- Number of vulnerabilities with high severity
    "v_medium"                                  INT     := 0; -- Number of vulnerabilities with medium severity
    "v_low"                                     INT     := 0; -- Number of vulnerabilities with low severity
    "v_unassigned"                              INT     := 0; -- Number of vulnerabilities with unassigned severity
    "v_risk_score"                              NUMERIC := 0; -- Inherited risk score
    "v_findings_total"                          INT     := 0; -- Total number of findings
    "v_findings_audited"                        INT     := 0; -- Number of audited findings
    "v_findings_unaudited"                      INT     := 0; -- Number of unaudited findings
    "v_findings_suppressed"                     INT     := 0; -- Number of suppressed findings
    "v_policy_violations_total"                 INT     := 0; -- Total number of policy violations
    "v_policy_violations_fail"                  INT     := 0; -- Number of policy violations with level fail
    "v_policy_violations_warn"                  INT     := 0; -- Number of policy violations with level warn
    "v_policy_violations_info"                  INT     := 0; -- Number of policy violations with level info
    "v_policy_violations_audited"               INT     := 0; -- Number of audited policy violations
    "v_policy_violations_unaudited"             INT     := 0; -- Number of unaudited policy violations
    "v_policy_violations_license_total"         INT     := 0; -- Total number of policy violations of type license
    "v_policy_violations_license_audited"       INT     := 0; -- Number of audited policy violations of type license
    "v_policy_violations_license_unaudited"     INT     := 0; -- Number of unaudited policy violations of type license
    "v_policy_violations_operational_total"     INT     := 0; -- Total number of policy violations of type operational
    "v_policy_violations_operational_audited"   INT     := 0; -- Number of audited policy violations of type operational
    "v_policy_violations_operational_unaudited" INT     := 0; -- Number of unaudited policy violations of type operational
    "v_policy_violations_security_total"        INT     := 0; -- Total number of policy violations of type security
    "v_policy_violations_security_audited"      INT     := 0; -- Number of audited policy violations of type security
    "v_policy_violations_security_unaudited"    INT     := 0; -- Number of unaudited policy violations of type security
    "v_existing_id"                             BIGINT; -- ID of the existing row that matches the data point calculated in this procedure
BEGIN
    SELECT "ID" FROM "PROJECT" WHERE "UUID" = "project_uuid" INTO "v_project_id";
    IF "v_project_id" IS NULL THEN
        RAISE EXCEPTION 'Project with UUID % does not exist', "project_uuid";
    END IF;

    SELECT COUNT(*)::INT,
           COALESCE(SUM(CASE WHEN "VULNERABILITIES" > 0 THEN 1 ELSE 0 END), 0),
           COALESCE(SUM("VULNERABILITIES")::INT, 0),
           COALESCE(SUM("CRITICAL")::INT, 0),
           COALESCE(SUM("HIGH")::INT, 0),
           COALESCE(SUM("MEDIUM")::INT, 0),
           COALESCE(SUM("LOW")::INT, 0),
           COALESCE(SUM("UNASSIGNED_SEVERITY")::INT, 0),
           COALESCE(SUM("FINDINGS_TOTAL")::INT, 0),
           COALESCE(SUM("FINDINGS_AUDITED")::INT, 0),
           COALESCE(SUM("FINDINGS_UNAUDITED")::INT, 0),
           COALESCE(SUM("SUPPRESSED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_FAIL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_WARN")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_INFO")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_UNAUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_LICENSE_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_LICENSE_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_LICENSE_UNAUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_OPERATIONAL_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_OPERATIONAL_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_OPERATIONAL_UNAUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_SECURITY_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_SECURITY_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_SECURITY_UNAUDITED")::INT, 0)
    FROM (SELECT DISTINCT ON ("DM"."COMPONENT_ID") *
          FROM "DEPENDENCYMETRICS" AS "DM"
          WHERE "PROJECT_ID" = "v_project_id"
          ORDER BY "DM"."COMPONENT_ID", "DM"."LAST_OCCURRENCE" DESC) AS "LATEST_COMPONENT_METRICS"
    INTO
        "v_components",
        "v_vulnerable_components",
        "v_vulnerabilities",
        "v_critical",
        "v_high",
        "v_medium",
        "v_low",
        "v_unassigned",
        "v_findings_total",
        "v_findings_audited",
        "v_findings_unaudited",
        "v_findings_suppressed",
        "v_policy_violations_total",
        "v_policy_violations_fail",
        "v_policy_violations_warn",
        "v_policy_violations_info",
        "v_policy_violations_audited",
        "v_policy_violations_unaudited",
        "v_policy_violations_license_total",
        "v_policy_violations_license_audited",
        "v_policy_violations_license_unaudited",
        "v_policy_violations_operational_total",
        "v_policy_violations_operational_audited",
        "v_policy_violations_operational_unaudited",
        "v_policy_violations_security_total",
        "v_policy_violations_security_audited",
        "v_policy_violations_security_unaudited";

    "v_risk_score" = "CALC_RISK_SCORE"("v_critical", "v_high", "v_medium", "v_low", "v_unassigned");

    SELECT DISTINCT ON ("ID") "ID"
    FROM "PROJECTMETRICS"
    WHERE "PROJECT_ID" = "v_project_id"
      AND "COMPONENTS" = "v_components"
      AND "VULNERABLECOMPONENTS" = "v_vulnerable_components"
      AND "VULNERABILITIES" = "v_vulnerabilities"
      AND "CRITICAL" = "v_critical"
      AND "HIGH" = "v_high"
      AND "MEDIUM" = "v_medium"
      AND "LOW" = "v_low"
      AND "UNASSIGNED_SEVERITY" = "v_unassigned"
      AND "RISKSCORE" = "v_risk_score"
      AND "FINDINGS_TOTAL" = "v_findings_total"
      AND "FINDINGS_AUDITED" = "v_findings_audited"
      AND "FINDINGS_UNAUDITED" = "v_findings_unaudited"
      AND "SUPPRESSED" = "v_findings_suppressed"
      AND "POLICYVIOLATIONS_TOTAL" = "v_policy_violations_total"
      AND "POLICYVIOLATIONS_FAIL" = "v_policy_violations_fail"
      AND "POLICYVIOLATIONS_WARN" = "v_policy_violations_warn"
      AND "POLICYVIOLATIONS_INFO" = "v_policy_violations_info"
      AND "POLICYVIOLATIONS_AUDITED" = "v_policy_violations_audited"
      AND "POLICYVIOLATIONS_UNAUDITED" = "v_policy_violations_unaudited"
      AND "POLICYVIOLATIONS_LICENSE_TOTAL" = "v_policy_violations_license_total"
      AND "POLICYVIOLATIONS_LICENSE_AUDITED" = "v_policy_violations_license_audited"
      AND "POLICYVIOLATIONS_LICENSE_UNAUDITED" = "v_policy_violations_license_unaudited"
      AND "POLICYVIOLATIONS_OPERATIONAL_TOTAL" = "v_policy_violations_operational_total"
      AND "POLICYVIOLATIONS_OPERATIONAL_AUDITED" = "v_policy_violations_operational_audited"
      AND "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" = "v_policy_violations_operational_unaudited"
      AND "POLICYVIOLATIONS_SECURITY_TOTAL" = "v_policy_violations_security_total"
      AND "POLICYVIOLATIONS_SECURITY_AUDITED" = "v_policy_violations_security_audited"
      AND "POLICYVIOLATIONS_SECURITY_UNAUDITED" = "v_policy_violations_security_unaudited"
    ORDER BY "ID", "LAST_OCCURRENCE" DESC
    LIMIT 1
    INTO "v_existing_id";

    IF "v_existing_id" IS NOT NULL THEN
        UPDATE "PROJECTMETRICS" SET "LAST_OCCURRENCE" = NOW() WHERE "ID" = "v_existing_id";
    ELSE
        INSERT INTO "PROJECTMETRICS" ("PROJECT_ID",
                                      "COMPONENTS",
                                      "VULNERABLECOMPONENTS",
                                      "VULNERABILITIES",
                                      "CRITICAL",
                                      "HIGH",
                                      "MEDIUM",
                                      "LOW",
                                      "UNASSIGNED_SEVERITY",
                                      "RISKSCORE",
                                      "FINDINGS_TOTAL",
                                      "FINDINGS_AUDITED",
                                      "FINDINGS_UNAUDITED",
                                      "SUPPRESSED",
                                      "POLICYVIOLATIONS_TOTAL",
                                      "POLICYVIOLATIONS_FAIL",
                                      "POLICYVIOLATIONS_WARN",
                                      "POLICYVIOLATIONS_INFO",
                                      "POLICYVIOLATIONS_AUDITED",
                                      "POLICYVIOLATIONS_UNAUDITED",
                                      "POLICYVIOLATIONS_LICENSE_TOTAL",
                                      "POLICYVIOLATIONS_LICENSE_AUDITED",
                                      "POLICYVIOLATIONS_LICENSE_UNAUDITED",
                                      "POLICYVIOLATIONS_OPERATIONAL_TOTAL",
                                      "POLICYVIOLATIONS_OPERATIONAL_AUDITED",
                                      "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
                                      "POLICYVIOLATIONS_SECURITY_TOTAL",
                                      "POLICYVIOLATIONS_SECURITY_AUDITED",
                                      "POLICYVIOLATIONS_SECURITY_UNAUDITED",
                                      "FIRST_OCCURRENCE",
                                      "LAST_OCCURRENCE")
        VALUES ("v_project_id",
                "v_components",
                "v_vulnerable_components",
                "v_vulnerabilities",
                "v_critical",
                "v_high",
                "v_medium",
                "v_low",
                "v_unassigned",
                "v_risk_score",
                "v_findings_total",
                "v_findings_audited",
                "v_findings_unaudited",
                "v_findings_suppressed",
                "v_policy_violations_total",
                "v_policy_violations_fail",
                "v_policy_violations_warn",
                "v_policy_violations_info",
                "v_policy_violations_audited",
                "v_policy_violations_unaudited",
                "v_policy_violations_license_total",
                "v_policy_violations_license_audited",
                "v_policy_violations_license_unaudited",
                "v_policy_violations_operational_total",
                "v_policy_violations_operational_audited",
                "v_policy_violations_operational_unaudited",
                "v_policy_violations_security_total",
                "v_policy_violations_security_audited",
                "v_policy_violations_security_unaudited",
                NOW(),
                NOW());

        UPDATE "PROJECT" SET "LAST_RISKSCORE" = "v_risk_score" WHERE "ID" = "v_project_id";
    END IF;
end;
$$;

--
CREATE OR REPLACE PROCEDURE "UPDATE_PORTFOLIO_METRICS"()
    LANGUAGE "plpgsql"
AS
$$
DECLARE
    "v_projects"                                INT; -- Total number of projects in the portfolio
    "v_vulnerable_projects"                     INT; -- Number of vulnerable projects in the portfolio
    "v_components"                              INT; -- Total number of components in the portfolio
    "v_vulnerable_components"                   INT; -- Number of vulnerable components in the portfolio
    "v_vulnerabilities"                         INT; -- Total number of vulnerabilities
    "v_critical"                                INT; -- Number of vulnerabilities with critical severity
    "v_high"                                    INT; -- Number of vulnerabilities with high severity
    "v_medium"                                  INT; -- Number of vulnerabilities with medium severity
    "v_low"                                     INT; -- Number of vulnerabilities with low severity
    "v_unassigned"                              INT; -- Number of vulnerabilities with unassigned severity
    "v_risk_score"                              NUMERIC; -- Inherited risk score
    "v_findings_total"                          INT; -- Total number of findings
    "v_findings_audited"                        INT; -- Number of audited findings
    "v_findings_unaudited"                      INT; -- Number of unaudited findings
    "v_findings_suppressed"                     INT; -- Number of suppressed findings
    "v_policy_violations_total"                 INT; -- Total number of policy violations
    "v_policy_violations_fail"                  INT; -- Number of policy violations with level fail
    "v_policy_violations_warn"                  INT; -- Number of policy violations with level warn
    "v_policy_violations_info"                  INT; -- Number of policy violations with level info
    "v_policy_violations_audited"               INT; -- Number of audited policy violations
    "v_policy_violations_unaudited"             INT; -- Number of unaudited policy violations
    "v_policy_violations_license_total"         INT; -- Total number of policy violations of type license
    "v_policy_violations_license_audited"       INT; -- Number of audited policy violations of type license
    "v_policy_violations_license_unaudited"     INT; -- Number of unaudited policy violations of type license
    "v_policy_violations_operational_total"     INT; -- Total number of policy violations of type operational
    "v_policy_violations_operational_audited"   INT; -- Number of audited policy violations of type operational
    "v_policy_violations_operational_unaudited" INT; -- Number of unaudited policy violations of type operational
    "v_policy_violations_security_total"        INT; -- Total number of policy violations of type security
    "v_policy_violations_security_audited"      INT; -- Number of audited policy violations of type security
    "v_policy_violations_security_unaudited"    INT; -- Number of unaudited policy violations of type security
    "v_existing_id"                             BIGINT; -- ID of the existing row that matches the data point calculated in this procedure
BEGIN
    SELECT COUNT(*)::INT,
           COALESCE(SUM(CASE WHEN "VULNERABILITIES" > 0 THEN 1 ELSE 0 END), 0),
           COUNT(*)::INT,
           COALESCE(SUM(CASE WHEN "VULNERABILITIES" > 0 THEN 1 ELSE 0 END), 0),
           COALESCE(SUM("VULNERABILITIES")::INT, 0),
           COALESCE(SUM("CRITICAL")::INT, 0),
           COALESCE(SUM("HIGH")::INT, 0),
           COALESCE(SUM("MEDIUM")::INT, 0),
           COALESCE(SUM("LOW")::INT, 0),
           COALESCE(SUM("UNASSIGNED_SEVERITY")::INT, 0),
           COALESCE(SUM("FINDINGS_TOTAL")::INT, 0),
           COALESCE(SUM("FINDINGS_AUDITED")::INT, 0),
           COALESCE(SUM("FINDINGS_UNAUDITED")::INT, 0),
           COALESCE(SUM("SUPPRESSED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_FAIL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_WARN")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_INFO")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_UNAUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_LICENSE_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_LICENSE_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_LICENSE_UNAUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_OPERATIONAL_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_OPERATIONAL_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_OPERATIONAL_UNAUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_SECURITY_TOTAL")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_SECURITY_AUDITED")::INT, 0),
           COALESCE(SUM("POLICYVIOLATIONS_SECURITY_UNAUDITED")::INT, 0)
    FROM (SELECT DISTINCT ON ("PM"."PROJECT_ID") *
          FROM "PROJECTMETRICS" AS "PM"
                   INNER JOIN "PROJECT" AS "P" ON "P"."ID" = "PM"."PROJECT_ID"
          WHERE "P"."ACTIVE" = TRUE  -- Only consider active projects
             OR "P"."ACTIVE" IS NULL -- ACTIVE is nullable, assume TRUE per default
          ORDER BY "PM"."PROJECT_ID", "PM"."LAST_OCCURRENCE" DESC) AS "LATEST_PROJECT_METRICS"
    INTO
        "v_projects",
        "v_vulnerable_projects",
        "v_components",
        "v_vulnerable_components",
        "v_vulnerabilities",
        "v_critical",
        "v_high",
        "v_medium",
        "v_low",
        "v_unassigned",
        "v_findings_total",
        "v_findings_audited",
        "v_findings_unaudited",
        "v_findings_suppressed",
        "v_policy_violations_total",
        "v_policy_violations_fail",
        "v_policy_violations_warn",
        "v_policy_violations_info",
        "v_policy_violations_audited",
        "v_policy_violations_unaudited",
        "v_policy_violations_license_total",
        "v_policy_violations_license_audited",
        "v_policy_violations_license_unaudited",
        "v_policy_violations_operational_total",
        "v_policy_violations_operational_audited",
        "v_policy_violations_operational_unaudited",
        "v_policy_violations_security_total",
        "v_policy_violations_security_audited",
        "v_policy_violations_security_unaudited";

    "v_risk_score" = "CALC_RISK_SCORE"("v_critical", "v_high", "v_medium", "v_low", "v_unassigned");

    SELECT DISTINCT ON ("ID") "ID"
    FROM "PORTFOLIOMETRICS"
    WHERE "PROJECTS" = "v_projects"
      AND "VULNERABLEPROJECTS" = "v_vulnerable_projects"
      AND "COMPONENTS" = "v_components"
      AND "VULNERABLECOMPONENTS" = "v_vulnerable_components"
      AND "VULNERABILITIES" = "v_vulnerabilities"
      AND "CRITICAL" = "v_critical"
      AND "HIGH" = "v_high"
      AND "MEDIUM" = "v_medium"
      AND "LOW" = "v_low"
      AND "UNASSIGNED_SEVERITY" = "v_unassigned"
      AND "RISKSCORE" = "v_risk_score"
      AND "FINDINGS_TOTAL" = "v_findings_total"
      AND "FINDINGS_AUDITED" = "v_findings_audited"
      AND "FINDINGS_UNAUDITED" = "v_findings_unaudited"
      AND "SUPPRESSED" = "v_findings_suppressed"
      AND "POLICYVIOLATIONS_TOTAL" = "v_policy_violations_total"
      AND "POLICYVIOLATIONS_FAIL" = "v_policy_violations_fail"
      AND "POLICYVIOLATIONS_WARN" = "v_policy_violations_warn"
      AND "POLICYVIOLATIONS_INFO" = "v_policy_violations_info"
      AND "POLICYVIOLATIONS_AUDITED" = "v_policy_violations_audited"
      AND "POLICYVIOLATIONS_UNAUDITED" = "v_policy_violations_unaudited"
      AND "POLICYVIOLATIONS_LICENSE_TOTAL" = "v_policy_violations_license_total"
      AND "POLICYVIOLATIONS_LICENSE_AUDITED" = "v_policy_violations_license_audited"
      AND "POLICYVIOLATIONS_LICENSE_UNAUDITED" = "v_policy_violations_license_unaudited"
      AND "POLICYVIOLATIONS_OPERATIONAL_TOTAL" = "v_policy_violations_operational_total"
      AND "POLICYVIOLATIONS_OPERATIONAL_AUDITED" = "v_policy_violations_operational_audited"
      AND "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED" = "v_policy_violations_operational_unaudited"
      AND "POLICYVIOLATIONS_SECURITY_TOTAL" = "v_policy_violations_security_total"
      AND "POLICYVIOLATIONS_SECURITY_AUDITED" = "v_policy_violations_security_audited"
      AND "POLICYVIOLATIONS_SECURITY_UNAUDITED" = "v_policy_violations_security_unaudited"
    ORDER BY "ID", "LAST_OCCURRENCE" DESC
    LIMIT 1
    INTO "v_existing_id";

    IF "v_existing_id" IS NOT NULL THEN
        UPDATE "PORTFOLIOMETRICS" SET "LAST_OCCURRENCE" = NOW() WHERE "ID" = "v_existing_id";
    ELSE
        INSERT INTO "PORTFOLIOMETRICS" ("PROJECTS",
                                        "VULNERABLEPROJECTS",
                                        "COMPONENTS",
                                        "VULNERABLECOMPONENTS",
                                        "VULNERABILITIES",
                                        "CRITICAL",
                                        "HIGH",
                                        "MEDIUM",
                                        "LOW",
                                        "UNASSIGNED_SEVERITY",
                                        "RISKSCORE",
                                        "FINDINGS_TOTAL",
                                        "FINDINGS_AUDITED",
                                        "FINDINGS_UNAUDITED",
                                        "SUPPRESSED",
                                        "POLICYVIOLATIONS_TOTAL",
                                        "POLICYVIOLATIONS_FAIL",
                                        "POLICYVIOLATIONS_WARN",
                                        "POLICYVIOLATIONS_INFO",
                                        "POLICYVIOLATIONS_AUDITED",
                                        "POLICYVIOLATIONS_UNAUDITED",
                                        "POLICYVIOLATIONS_LICENSE_TOTAL",
                                        "POLICYVIOLATIONS_LICENSE_AUDITED",
                                        "POLICYVIOLATIONS_LICENSE_UNAUDITED",
                                        "POLICYVIOLATIONS_OPERATIONAL_TOTAL",
                                        "POLICYVIOLATIONS_OPERATIONAL_AUDITED",
                                        "POLICYVIOLATIONS_OPERATIONAL_UNAUDITED",
                                        "POLICYVIOLATIONS_SECURITY_TOTAL",
                                        "POLICYVIOLATIONS_SECURITY_AUDITED",
                                        "POLICYVIOLATIONS_SECURITY_UNAUDITED",
                                        "FIRST_OCCURRENCE",
                                        "LAST_OCCURRENCE")
        VALUES ("v_projects",
                "v_vulnerable_projects",
                "v_components",
                "v_vulnerable_components",
                "v_vulnerabilities",
                "v_critical",
                "v_high",
                "v_medium",
                "v_low",
                "v_unassigned",
                "v_risk_score",
                "v_findings_total",
                "v_findings_audited",
                "v_findings_unaudited",
                "v_findings_suppressed",
                "v_policy_violations_total",
                "v_policy_violations_fail",
                "v_policy_violations_warn",
                "v_policy_violations_info",
                "v_policy_violations_audited",
                "v_policy_violations_unaudited",
                "v_policy_violations_license_total",
                "v_policy_violations_license_audited",
                "v_policy_violations_license_unaudited",
                "v_policy_violations_operational_total",
                "v_policy_violations_operational_audited",
                "v_policy_violations_operational_unaudited",
                "v_policy_violations_security_total",
                "v_policy_violations_security_audited",
                "v_policy_violations_security_unaudited",
                NOW(),
                NOW());
    END IF;
END;
$$;