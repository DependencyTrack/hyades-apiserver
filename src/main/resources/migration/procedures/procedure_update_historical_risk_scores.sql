CREATE OR REPLACE PROCEDURE "UPDATE_HISTORICAL_RISK_SCORES"()
   LANGUAGE "plpgsql"
AS
$$
DECLARE 
  "v_critical"                                INT; -- Number of vulnerabilities with critical severity
  "v_high"                                    INT; -- Number of vulnerabilities with high severity
  "v_medium"                                  INT; -- Number of vulnerabilities with medium severity
  "v_low"                                     INT; -- Number of vulnerabilities with low severity
  "v_unassigned"                              INT; -- Number of vulnerabilities with unassigned severity
  "v_risk_score"                              NUMERIC; -- Inherited risk score
BEGIN 
    UPDATE "DEPENDENCYMETRICS" SET "v_risk_score" = "CALC_RISK_SCORE"("v_critical", "v_high", "v_medium", "v_low", "v_unassigned");
$$;