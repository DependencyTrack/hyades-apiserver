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
  rec record;
  project_id integer;
BEGIN
  IF TG_TABLE_NAME = 'PROJECT_ACCESS_TEAMS' THEN
    FOR rec IN (SELECT DISTINCT "PROJECT_ID" FROM old_table) LOOP
      PERFORM recalc_user_project_effective_permissions(rec."PROJECT_ID");
    END LOOP;

  ELSIF TG_TABLE_NAME IN ('LDAPUSERS_TEAMS', 'MANAGEDUSERS_TEAMS', 'OIDCUSERS_TEAMS') THEN
    FOR rec IN (SELECT DISTINCT "TEAM_ID" FROM old_table) LOOP
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
