-- Calculate the severity of a vulnerability based on its CVSSv3 base score.
CREATE OR REPLACE FUNCTION "CVSSV3_TO_SEVERITY"(
  "base_score" NUMERIC
) RETURNS VARCHAR
  LANGUAGE "sql"
  PARALLEL SAFE
  IMMUTABLE
AS
$$
SELECT
  CASE
    WHEN "base_score" >= 9 THEN 'CRITICAL'
    WHEN "base_score" >= 7 THEN 'HIGH'
    WHEN "base_score" >= 4 THEN 'MEDIUM'
    WHEN "base_score" > 0 THEN 'LOW'
    ELSE 'UNASSIGNED'
  END;
$$;