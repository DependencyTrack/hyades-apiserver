-- INSERT trigger for PROJECT_ACCESS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_project_access_teams_insert
AFTER INSERT ON public."PROJECT_ACCESS_TEAMS"
REFERENCING NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_insert();

-- DELETE trigger for PROJECT_ACCESS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_project_access_teams_delete
AFTER DELETE ON public."PROJECT_ACCESS_TEAMS"
REFERENCING OLD TABLE AS old_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_delete();

-- UPDATE trigger for PROJECT_ACCESS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_project_access_teams_update
AFTER UPDATE ON public."PROJECT_ACCESS_TEAMS"
REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_update();

-- INSERT trigger for LDAPUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_ldapusers_teams_insert
AFTER INSERT ON public."LDAPUSERS_TEAMS"
REFERENCING NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_insert();

-- DELETE trigger for LDAPUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_ldapusers_teams_delete
AFTER DELETE ON public."LDAPUSERS_TEAMS"
REFERENCING OLD TABLE AS old_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_delete();

-- UPDATE trigger for LDAPUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_ldapusers_teams_update
AFTER UPDATE ON public."LDAPUSERS_TEAMS"
REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_update();

-- INSERT trigger for MANAGEDUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_managedusers_teams_insert
AFTER INSERT ON public."MANAGEDUSERS_TEAMS"
REFERENCING NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_insert();

-- DELETE trigger for MANAGEDUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_managedusers_teams_delete
AFTER DELETE ON public."MANAGEDUSERS_TEAMS"
REFERENCING OLD TABLE AS old_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_delete();

-- UPDATE trigger for MANAGEDUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_managedusers_teams_update
AFTER UPDATE ON public."MANAGEDUSERS_TEAMS"
REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_update();

-- INSERT trigger for OIDCUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_oidcusers_teams_insert
AFTER INSERT ON public."OIDCUSERS_TEAMS"
REFERENCING NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_insert();

-- DELETE trigger for OIDCUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_oidcusers_teams_delete
AFTER DELETE ON public."OIDCUSERS_TEAMS"
REFERENCING OLD TABLE AS old_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_delete();

-- UPDATE trigger for OIDCUSERS_TEAMS
CREATE TRIGGER trigger_effective_permissions_mx_on_oidcusers_teams_update
AFTER UPDATE ON public."OIDCUSERS_TEAMS"
REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION effective_permissions_mx_on_update();

-- Prevent direct inserts/updates/writes to USER_PROJECT_EFFECTIVE_PERMISSIONS
CREATE TRIGGER trigger_prevent_direct_effective_permissions_writes
BEFORE DELETE OR INSERT OR UPDATE ON public."USER_PROJECT_EFFECTIVE_PERMISSIONS"
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_direct_effective_permissions_writes();
