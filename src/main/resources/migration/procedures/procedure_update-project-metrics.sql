CREATE OR REPLACE PROCEDURE "UPDATE_PROJECT_METRICS"(
  "project_uuid" UUID
)
  LANGUAGE "plpgsql"
AS
$$
DECLARE
  "v_project_id"                              BIGINT;
  "v_component_uuid"                          UUID;
  "v_components"                              INT; -- Total number of components in the project
  "v_vulnerable_components"                   INT; -- Number of vulnerable components in the project
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
  SELECT "ID" FROM "PROJECT" WHERE "UUID" = "project_uuid" INTO "v_project_id";
  IF "v_project_id" IS NULL THEN
    RAISE EXCEPTION 'Project with UUID % does not exist', "project_uuid";
  END IF;

  FOR "v_component_uuid" IN SELECT "UUID" FROM "COMPONENT" WHERE "PROJECT_ID" = "v_project_id"
  LOOP
    CALL "UPDATE_COMPONENT_METRICS"("v_component_uuid");
  END LOOP;

  -- Aggregate over all most recent DEPENDENCYMETRICS.
  -- NOTE: SUM returns NULL when no rows match the query, but COUNT returns 0.
  -- For nullable result columns, use COALESCE(..., 0) to have a default value.
  SELECT COUNT(*)::INT,
    COALESCE(SUM(CASE WHEN "VULNERABILITIES" > 0 THEN 1 ELSE 0 END)::INT, 0),
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

  WITH "CTE_LATEST_METRICS" AS (
    SELECT *
      FROM "PROJECTMETRICS"
     WHERE "PROJECT_ID" = "v_project_id"
     ORDER BY "LAST_OCCURRENCE" DESC
     LIMIT 1)
  SELECT "ID"
  FROM "CTE_LATEST_METRICS"
  WHERE "COMPONENTS" = "v_components"
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