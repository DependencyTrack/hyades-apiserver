-- DEPRECATED: Do not use, except through DataNucleus methods!
-- Calling this function produces suboptimal query plans.
-- https://github.com/DependencyTrack/hyades/issues/1801
CREATE OR REPLACE FUNCTION has_user_project_access(
  project_id BIGINT
, user_id BIGINT
) RETURNS BOOL
  LANGUAGE "sql"
  PARALLEL SAFE
  STABLE
AS
$$
SELECT EXISTS(
  SELECT 1
    FROM "USER_PROJECT_EFFECTIVE_PERMISSIONS" AS upep
   INNER JOIN "PROJECT_HIERARCHY" AS ph
      ON ph."PARENT_PROJECT_ID" = upep."PROJECT_ID"
   WHERE ph."CHILD_PROJECT_ID" = project_id
     AND upep."USER_ID" = user_id
     AND upep."PERMISSION_NAME" = 'VIEW_PORTFOLIO'
)
$$;