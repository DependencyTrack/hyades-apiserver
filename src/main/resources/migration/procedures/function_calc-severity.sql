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
  LANGUAGE "plpgsql"
AS
$$
BEGIN
  IF "severity_override" IS NOT NULL THEN
    RETURN "severity_override";
  ELSEIF "cvssv3_base_score" IS NOT NULL THEN
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