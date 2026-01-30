-- DEPRECATED: Do not use, except through DataNucleus methods!
-- Calling this function produces suboptimal query plans.
-- https://github.com/DependencyTrack/hyades/issues/1801
CREATE OR REPLACE FUNCTION has_project_access(
  project_id BIGINT
, team_ids BIGINT[]
) RETURNS BOOL
  LANGUAGE "sql"
  PARALLEL SAFE
  STABLE
AS
$$
SELECT EXISTS(
  SELECT 1
    FROM "PROJECT_ACCESS_TEAMS" AS pat
   INNER JOIN "PROJECT_HIERARCHY" AS ph
      ON ph."PARENT_PROJECT_ID" = pat."PROJECT_ID"
   WHERE pat."TEAM_ID" = ANY(team_ids)
     AND ph."CHILD_PROJECT_ID" = project_id
)
$$;