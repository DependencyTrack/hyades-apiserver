-- Trigger function to prevent direct modification of USER_PROJECT_EFFECTIVE_PERMISSIONS

CREATE OR REPLACE FUNCTION prevent_direct_effective_permissions_writes()
RETURNS TRIGGER AS $$
BEGIN
  -- Depth of 1 means this trigger was fired by an attempted direct
  -- insert, update, or delete on USER_PROJECT_EFFECTIVE_PERMISSIONS.
  -- Depth should be 2, meaning this trigger was fired from another trigger.
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'Direct modifications to USER_PROJECT_EFFECTIVE_PERMISSIONS are not allowed.';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
