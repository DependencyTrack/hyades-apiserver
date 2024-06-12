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
  LANGUAGE "sql"
  PARALLEL SAFE
  IMMUTABLE
AS
$$
WITH "CUSTOM_SCORES" AS (
  SELECT "PROPERTYVALUE"::INT AS "value"
       , "PROPERTYNAME" AS "name"
    FROM "CONFIGPROPERTY"
   WHERE "PROPERTYGROUP" = 'risk-score'
     AND "PROPERTYTYPE" = 'INTEGER'
)
SELECT (
  ("critical" * (SELECT "value" FROM "CUSTOM_SCORES" WHERE "name" = 'riskscore.critical'))
  + ("high" * (SELECT "value" FROM "CUSTOM_SCORES" WHERE "name" = 'riskscore.high'))
  + ("medium" * (SELECT "value" FROM "CUSTOM_SCORES" WHERE "name" = 'riskscore.medium'))
  + ("low" * (SELECT "value" FROM "CUSTOM_SCORES" WHERE "name" = 'riskscore.low'))
  + ("unassigned" * (SELECT "value" FROM "CUSTOM_SCORES" WHERE "name" = 'riskscore.unassigned'))
)::NUMERIC;
$$;