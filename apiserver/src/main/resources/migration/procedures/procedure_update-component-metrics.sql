CREATE OR REPLACE PROCEDURE "UPDATE_COMPONENT_METRICS"(
  "component_uuid" UUID
)
  LANGUAGE "plpgsql"
AS
$$
DECLARE
  "v_component"                               RECORD; -- The component to update metrics for
  "v_vulnerability"                           RECORD; -- Loop variable for iterating over vulnerabilities the component is affected by
  "v_alias"                                   RECORD; -- Loop variable for iterating over aliases of a vulnerability
  "v_aliases_seen"                            TEXT[]; -- Array of aliases encountered while iterating over vulnerabilities
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

  FOR "v_vulnerability" IN SELECT "VULNID", "SOURCE", "V"."SEVERITY", "A"."SEVERITY" AS "SEVERITY_OVERRIDE", "CVSSV2BASESCORE", "CVSSV3BASESCORE"
                           FROM "VULNERABILITY" AS "V"
                                  INNER JOIN "COMPONENTS_VULNERABILITIES" AS "CV"
                                             ON "CV"."COMPONENT_ID" = "v_component"."ID"
                                               AND "CV"."VULNERABILITY_ID" = "V"."ID"
                                  LEFT OUTER JOIN "ANALYSIS" AS "A"
                                        ON "A"."COMPONENT_ID" = "v_component"."ID"
                                            AND "A"."COMPONENT_ID" = "CV"."COMPONENT_ID"
                                            AND "A"."VULNERABILITY_ID" = "V"."ID"
                                        WHERE "A"."SUPPRESSED" != TRUE OR "A"."SUPPRESSED" IS NULL
    LOOP
      CONTINUE WHEN ("v_vulnerability"."SOURCE" || '|' || "v_vulnerability"."VULNID") = ANY ("v_aliases_seen");

      FOR "v_alias" IN SELECT *
                       FROM "VULNERABILITYALIAS" AS "VA"
                       WHERE ("v_vulnerability"."SOURCE" = 'GITHUB' AND
                              "VA"."GHSA_ID" = "v_vulnerability"."VULNID")
                         OR ("v_vulnerability"."SOURCE" = 'INTERNAL' AND
                             "VA"."INTERNAL_ID" = "v_vulnerability"."VULNID")
                         OR ("v_vulnerability"."SOURCE" = 'NVD' AND
                             "VA"."CVE_ID" = "v_vulnerability"."VULNID")
                         OR ("v_vulnerability"."SOURCE" = 'OSSINDEX' AND
                             "VA"."SONATYPE_ID" = "v_vulnerability"."VULNID")
                         OR ("v_vulnerability"."SOURCE" = 'OSV' AND
                             "VA"."OSV_ID" = "v_vulnerability"."VULNID")
                         OR ("v_vulnerability"."SOURCE" = 'SNYK' AND
                             "VA"."SNYK_ID" = "v_vulnerability"."VULNID")
                         OR ("v_vulnerability"."SOURCE" = 'VULNDB' AND
                             "VA"."VULNDB_ID" = "v_vulnerability"."VULNID")
        LOOP
          IF "v_alias"."GHSA_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'GITHUB|' || "v_alias"."GHSA_ID");
          END IF;
          IF "v_alias"."INTERNAL_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'INTERNAL|' || "v_alias"."INTERNAL_ID");
          END IF;
          IF "v_alias"."CVE_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'NVD|' || "v_alias"."CVE_ID");
          END IF;
          IF "v_alias"."SONATYPE_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'OSSINDEX|' || "v_alias"."SONATYPE_ID");
          END IF;
          IF "v_alias"."OSV_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'OSV|' || "v_alias"."OSV_ID");
          END IF;
          IF "v_alias"."SNYK_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'SNYK|' || "v_alias"."SNYK_ID");
          END IF;
          IF "v_alias"."VULNDB_ID" IS NOT NULL THEN
            "v_aliases_seen" = array_append("v_aliases_seen", 'VULNDB|' || "v_alias"."VULNDB_ID");
          END IF;
        END LOOP;

      "v_vulnerabilities" := "v_vulnerabilities" + 1;

      IF COALESCE("v_vulnerability"."SEVERITY_OVERRIDE", "v_vulnerability"."SEVERITY") = 'CRITICAL' THEN
        "v_critical" := "v_critical" + 1;
      ELSEIF COALESCE("v_vulnerability"."SEVERITY_OVERRIDE", "v_vulnerability"."SEVERITY") = 'HIGH' THEN
        "v_high" := "v_high" + 1;
      ELSEIF COALESCE("v_vulnerability"."SEVERITY_OVERRIDE", "v_vulnerability"."SEVERITY") = 'MEDIUM' THEN
        "v_medium" := "v_medium" + 1;
      ELSEIF COALESCE("v_vulnerability"."SEVERITY_OVERRIDE", "v_vulnerability"."SEVERITY") = 'LOW' THEN
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

  WITH "CTE_LATEST_METRICS" AS (
    SELECT *
      FROM "DEPENDENCYMETRICS"
     WHERE "COMPONENT_ID" = "v_component"."ID"
     ORDER BY "LAST_OCCURRENCE" DESC
     LIMIT 1)
  SELECT "ID"
  FROM "CTE_LATEST_METRICS"
  WHERE "VULNERABILITIES" = "v_vulnerabilities"
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