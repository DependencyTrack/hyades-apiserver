/* Trigger function to update the values in the USER_PROJECT_EFFECTIVE_PERMISSIONS table.

Fired on DELETE FROM one of:
  - PROJECT_ACCESS_TEAMS
  - LDAPUSERS_TEAMS
  - MANAGEDUSERS_TEAMS
  - OIDCUSERS_TEAMS
*/

CREATE OR REPLACE FUNCTION effective_permissions_mx_on_delete()
RETURNS TRIGGER AS $$
DECLARE
  project_ids BIGINT[];
BEGIN
  IF TG_TABLE_NAME = 'PROJECT_ACCESS_TEAMS' THEN
    PERFORM recalc_user_project_effective_permissions(
      (SELECT ARRAY_AGG(DISTINCT "PROJECT_ID") FROM old_table)
    );
  ELSIF TG_TABLE_NAME IN ('LDAPUSERS_TEAMS', 'MANAGEDUSERS_TEAMS', 'OIDCUSERS_TEAMS') THEN
    PERFORM recalc_user_project_effective_permissions((
      SELECT ARRAY_AGG(DISTINCT pat."PROJECT_ID")
      FROM "PROJECT_ACCESS_TEAMS" AS pat
      INNER JOIN old_table
        ON old_table."TEAM_ID" = pat."TEAM_ID"
    ));
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
