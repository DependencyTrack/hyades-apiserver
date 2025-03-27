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
  rec        RECORD;
  project_id BIGINT;
BEGIN
  IF TG_TABLE_NAME = 'PROJECT_ACCESS_TEAMS' THEN
    -- For this table we can get PROJECT_ID directly.
    FOR rec IN (SELECT DISTINCT "PROJECT_ID" FROM new_table) LOOP
      PERFORM recalc_user_project_effective_permissions(rec."PROJECT_ID");
    END LOOP;

  ELSIF TG_TABLE_NAME IN ('LDAPUSERS_TEAMS', 'MANAGEDUSERS_TEAMS', 'OIDCUSERS_TEAMS') THEN
    -- For user-team linking tables get the team IDs and then their projects.
    FOR rec IN (SELECT DISTINCT "TEAM_ID" FROM new_table) LOOP
      FOR project_id IN
        SELECT DISTINCT "PROJECT_ID"
        FROM public."PROJECT_ACCESS_TEAMS"
        WHERE "TEAM_ID" = rec."TEAM_ID"
      LOOP
        PERFORM recalc_user_project_effective_permissions(project_id);
      END LOOP;
    END LOOP;
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
