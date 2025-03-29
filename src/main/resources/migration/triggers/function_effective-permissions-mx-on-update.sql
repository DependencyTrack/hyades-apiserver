/* Trigger function to update the values in the USER_PROJECT_EFFECTIVE_PERMISSIONS table.

Fired on UPDATE for one of:
  - PROJECT_ACCESS_TEAMS
  - LDAPUSERS_TEAMS
  - MANAGEDUSERS_TEAMS
  - OIDCUSERS_TEAMS
*/

CREATE OR REPLACE FUNCTION effective_permissions_mx_on_update()
RETURNS TRIGGER AS $$
DECLARE
  project_ids BIGINT[];
BEGIN
  IF TG_TABLE_NAME = 'PROJECT_ACCESS_TEAMS' THEN
    PERFORM recalc_user_project_effective_permissions((
      SELECT ARRAY_AGG("PROJECT_ID")
      FROM (
        SELECT "PROJECT_ID" FROM old_table
        UNION
        SELECT "PROJECT_ID" FROM new_table
        ) AS combined_projects
    ));
  ELSIF TG_TABLE_NAME IN ('LDAPUSERS_TEAMS', 'MANAGEDUSERS_TEAMS', 'OIDCUSERS_TEAMS') THEN
    PERFORM recalc_user_project_effective_permissions(
      ARRAY(
        SELECT DISTINCT pat."PROJECT_ID"
        FROM "PROJECT_ACCESS_TEAMS" pat
        JOIN (
          SELECT "TEAM_ID" FROM old_table
          UNION
          SELECT "TEAM_ID" FROM new_table
        ) AS teams
          ON pat."TEAM_ID" = teams."TEAM_ID"
      )
    );
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
