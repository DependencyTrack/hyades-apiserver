-- Calculate the severity of a vulnerability based on:
--   * a pre-set severity
--   * a CVSSv3 base score
--   * a CVSSv2 base score
-- The behavior of this function is identical to Vulnerability#getSeverity
-- in the API server Java code base.
-- https://github.com/DependencyTrack/dependency-track/blob/1976be1f5cc9d027900f09aed9d1539595aeda3a/src/main/java/org/dependencytrack/model/Vulnerability.java#L338-L340
CREATE OR REPLACE FUNCTION "CALC_SEVERITY"(
  "severity" VARCHAR,
  "severity_override" VARCHAR,
  "cvssv3_base_score" NUMERIC,
  "cvssv2_base_score" NUMERIC
) RETURNS VARCHAR
  LANGUAGE "sql"
  PARALLEL SAFE
  IMMUTABLE
AS
$$
SELECT
  CASE
    WHEN "severity_override" IS NOT NULL THEN "severity_override"
    WHEN "cvssv3_base_score" IS NOT NULL THEN "CVSSV3_TO_SEVERITY"("cvssv3_base_score")
    WHEN "cvssv2_base_score" IS NOT NULL THEN "CVSSV2_TO_SEVERITY"("cvssv2_base_score")
    WHEN "severity" IS NOT NULL THEN "severity"
    ELSE 'UNASSIGNED'
  END;
$$;