/* Trigger function to update the values in the USER_PROJECT_EFFECTIVE_PERMISSIONS table.

Fired on INSERT INTO one of:
  - PROJECT_ACCESS_TEAMS
  - LDAPUSERS_TEAMS
  - MANAGEDUSERS_TEAMS
  - OIDCUSERS_TEAMS
*/

CREATE OR REPLACE FUNCTION effective_permissions_mx_on_insert()
RETURNS TRIGGER AS $$
DECLARE
  project_ids BIGINT[];
BEGIN
  IF TG_TABLE_NAME = 'PROJECT_ACCESS_TEAMS' THEN
    PERFORM recalc_user_project_effective_permissions(
      (SELECT ARRAY_AGG(DISTINCT "PROJECT_ID") FROM new_table)
    );
  ELSIF TG_TABLE_NAME IN ('LDAPUSERS_TEAMS', 'MANAGEDUSERS_TEAMS', 'OIDCUSERS_TEAMS') THEN
    PERFORM recalc_user_project_effective_permissions(
      ARRAY(
        SELECT DISTINCT pat."PROJECT_ID"
        FROM "PROJECT_ACCESS_TEAMS" AS pat
        INNER JOIN new_table
          ON new_table."TEAM_ID" = pat."TEAM_ID"
      )
    );
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
