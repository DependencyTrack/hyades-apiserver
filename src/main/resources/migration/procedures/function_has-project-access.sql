create or replace function has_project_access(
  project_id bigint
, team_ids bigint[]
) returns bool
  language "sql"
  parallel safe
  stable
as
$$
select exists(
  select 1
    from "PROJECT_ACCESS_TEAMS"
   inner join "PROJECT_HIERARCHY"
      on "PROJECT_HIERARCHY"."PARENT_PROJECT_ID" = "PROJECT_ACCESS_TEAMS"."PROJECT_ID"
   where "PROJECT_ACCESS_TEAMS"."TEAM_ID" = any(team_ids)
     and "PROJECT_HIERARCHY"."CHILD_PROJECT_ID" = project_id
)
$$;