-- Helper function to recalculate all user permissions for a project.
-- Called by trigger functions to update the values in the USER_PROJECT_EFFECTIVE_PERMISSIONS table.

CREATE OR REPLACE FUNCTION recalc_user_project_effective_permissions(project_id BIGINT)
RETURNS void AS $$
BEGIN
  -- Remove any existing effective permissions for this project.
  DELETE FROM public."USER_PROJECT_EFFECTIVE_PERMISSIONS"
  WHERE "PROJECT_ID" = project_id;

  -- Rebuild effective permissions for LDAP users
  INSERT INTO public."USER_PROJECT_EFFECTIVE_PERMISSIONS"
    ("LDAPUSER_ID", "PROJECT_ID", "PERMISSION_ID", "PERMISSION_NAME")
  SELECT DISTINCT lut."LDAPUSER_ID", pat."PROJECT_ID", tp."PERMISSION_ID", p."NAME"
  FROM public."PROJECT_ACCESS_TEAMS" pat
    JOIN public."TEAMS_PERMISSIONS" tp ON tp."TEAM_ID" = pat."TEAM_ID"
    JOIN public."PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
    JOIN public."LDAPUSERS_TEAMS" lut ON lut."TEAM_ID" = pat."TEAM_ID"
  WHERE pat."PROJECT_ID" = project_id;

  -- Rebuild effective permissions for managed users
  INSERT INTO public."USER_PROJECT_EFFECTIVE_PERMISSIONS"
    ("MANAGEDUSER_ID", "PROJECT_ID", "PERMISSION_ID", "PERMISSION_NAME")
  SELECT DISTINCT mut."MANAGEDUSER_ID", pat."PROJECT_ID", tp."PERMISSION_ID", p."NAME"
  FROM public."PROJECT_ACCESS_TEAMS" pat
    JOIN public."TEAMS_PERMISSIONS" tp ON tp."TEAM_ID" = pat."TEAM_ID"
    JOIN public."PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
    JOIN public."MANAGEDUSERS_TEAMS" mut ON mut."TEAM_ID" = pat."TEAM_ID"
  WHERE pat."PROJECT_ID" = project_id;

  -- Rebuild effective permissions for OIDC users
  INSERT INTO public."USER_PROJECT_EFFECTIVE_PERMISSIONS"
    ("OIDCUSER_ID", "PROJECT_ID", "PERMISSION_ID", "PERMISSION_NAME")
  SELECT DISTINCT outt."OIDCUSERS_ID", pat."PROJECT_ID", tp."PERMISSION_ID", p."NAME"
  FROM public."PROJECT_ACCESS_TEAMS" pat
    JOIN public."TEAMS_PERMISSIONS" tp ON tp."TEAM_ID" = pat."TEAM_ID"
    JOIN public."PERMISSION" p ON p."ID" = tp."PERMISSION_ID"
    JOIN public."OIDCUSERS_TEAMS" outt ON outt."TEAM_ID" = pat."TEAM_ID"
  WHERE pat."PROJECT_ID" = project_id;
END;
$$ LANGUAGE plpgsql;
