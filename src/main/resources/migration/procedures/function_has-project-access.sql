create or replace function has_project_access(
  project_id bigint
, team_ids bigint[]
) returns bool
  language "sql"
  parallel safe
  stable
as
$$
with recursive project_hierarchy(id, parent_id) as(
  select "ID" as id
       , "PARENT_PROJECT_ID" as parent_id
    from "PROJECT"
   where "ID" = project_id
   union all
  select "PROJECT"."ID" as id
       , "PROJECT"."PARENT_PROJECT_ID" as parent_id
    from "PROJECT"
   inner join project_hierarchy
      on project_hierarchy.parent_id = "PROJECT"."ID"
)
select exists(
  select 1
    from project_hierarchy
   inner join "PROJECT_ACCESS_TEAMS"
      on "PROJECT_ACCESS_TEAMS"."PROJECT_ID" = project_hierarchy.id
   where "PROJECT_ACCESS_TEAMS"."TEAM_ID" = any(team_ids)
)
$$;