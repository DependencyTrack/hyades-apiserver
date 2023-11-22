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