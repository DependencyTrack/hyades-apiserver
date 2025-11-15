create type workflow_run_status as enum (
  'CREATED'
, 'RUNNING'
, 'SUSPENDED'
, 'CANCELED'
, 'COMPLETED'
, 'FAILED'
);

create table workflow_run (
  id uuid
, parent_id uuid
, workflow_name text not null
, workflow_version smallint not null
, status workflow_run_status not null default 'CREATED'
, custom_status text
, concurrency_group_id text
, priority smallint not null
, labels jsonb
, locked_by text
, locked_until timestamptz(3)
, created_at timestamptz(3) not null
, updated_at timestamptz(3)
, started_at timestamptz(3)
, completed_at timestamptz(3)
, constraint workflow_run_pk primary key (id)
, constraint workflow_run_parent_fk foreign key (parent_id) references workflow_run (id) on delete cascade
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 90);

create table workflow_run_concurrency_group (
  id text
, next_run_id uuid not null
, constraint workflow_run_concurrency_group_pk primary key (id)
, constraint workflow_run_concurrency_group_next_run_fk foreign key (next_run_id) references workflow_run (id) on delete cascade
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 90);

create table workflow_run_history (
  workflow_run_id uuid
, sequence_number int
, event bytea not null
, constraint workflow_run_history_pk primary key (workflow_run_id, sequence_number)
, constraint workflow_run_history_workflow_run_fk foreign key (workflow_run_id) references workflow_run (id) on delete cascade
);

create table workflow_run_inbox (
  id bigint generated always as identity
, workflow_run_id uuid not null
, visible_from timestamptz(3)
, locked_by text
, dequeue_count smallint
, event bytea not null
, constraint workflow_run_inbox_pk primary key (id)
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 90);

create type workflow_queue_status as enum (
  'ACTIVE'
, 'PAUSED'
);

create table workflow_activity_task_queue (
  name text
, status workflow_queue_status not null default 'ACTIVE'
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint workflow_activity_task_queue_pk primary key (name)
);

create table workflow_activity_task (
  workflow_run_id uuid
, created_event_id int
, activity_name text not null
, queue_name text not null
, priority smallint not null
, argument bytea
, visible_from timestamptz(3)
, locked_by text
, locked_until timestamptz(3)
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint workflow_activity_task_pk primary key (workflow_run_id, created_event_id)
, constraint workflow_activity_task_workflow_run_fk foreign key (workflow_run_id) references workflow_run (id) on delete cascade
, constraint workflow_activity_task_queue_fk foreign key (queue_name) references workflow_activity_task_queue (name)
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 90);

create index workflow_run_poll_idx
    on workflow_run (priority desc, id, workflow_name)
 where status = any(cast('{CREATED, RUNNING, SUSPENDED}' as workflow_run_status[]));

create index workflow_run_concurrency_group_update_idx
    on workflow_run (concurrency_group_id, priority desc, id)
 where status = cast('CREATED' as workflow_run_status)
   and concurrency_group_id is not null;

create index workflow_run_labels_idx
    on workflow_run using gin (labels jsonb_path_ops)
    where labels is not null;

create index workflow_run_created_at_idx
    on workflow_run (created_at);

create index workflow_run_completed_at_idx
    on workflow_run (completed_at)
    where completed_at is not null;

create index workflow_run_inbox_workflow_run_id_idx
    on workflow_run_inbox (workflow_run_id);

create index workflow_activity_task_poll_idx
    on workflow_activity_task (priority desc, created_at, activity_name, queue_name);

create function create_workflow_run_concurrency_groups_on_run_creation()
returns trigger
as $$
begin
  insert into workflow_run_concurrency_group (id, next_run_id)
  select distinct on (concurrency_group_id)
         concurrency_group_id
       , id
    from new_table
   where concurrency_group_id is not null
   order by concurrency_group_id
          , priority desc
          , id
  on conflict (id) do nothing;
  return null;
end;
$$ language plpgsql;

create function update_workflow_run_concurrency_groups_on_run_completion()
returns trigger
as $$
declare
  group_ids text[];
  updated_group_ids text[];
begin
  -- Identify concurrency group IDs for which runs have transitioned
  -- from a non-terminal to a terminal status.
  select array_agg(distinct new_table.concurrency_group_id)
    into group_ids
    from new_table
   inner join old_table
      on old_table.id = new_table.id
   where old_table.status = any(cast('{CREATED, RUNNING, SUSPENDED}' as workflow_run_status[]))
     and new_table.status = any(cast('{CANCELED, COMPLETED, FAILED}' as workflow_run_status[]))
     and new_table.concurrency_group_id is not null;

  if coalesce(array_length(group_ids, 1), 0) = 0 then
    return null;
  end if;

  -- Identify and set the next run to execute for each concurrency group ID.
  with
  cte_next_run as (
    select distinct on (concurrency_group_id)
           concurrency_group_id
         , id
      from workflow_run
     where concurrency_group_id = any(group_ids)
       and status = cast('CREATED' as workflow_run_status)
     order by concurrency_group_id
            , priority desc
            , id
  ),
  cte_updated_group as (
    update workflow_run_concurrency_group
       set next_run_id = cte_next_run.id
      from cte_next_run
     where workflow_run_concurrency_group.id = cte_next_run.concurrency_group_id
    returning workflow_run_concurrency_group.id
  )
  select array_agg(id)
    into updated_group_ids
    from cte_updated_group;

  if coalesce(array_length(updated_group_ids, 1), 0) = array_length(group_ids, 1) then
    return null;
  end if;

  -- Delete concurrency groups for which no next run could be determined.
  delete
    from workflow_run_concurrency_group
   where id = any(group_ids)
     and id != all(updated_group_ids);

  return null;
end;
$$ language plpgsql;

create trigger trigger_create_workflow_run_concurrency_groups_on_run_creation
after insert on workflow_run
referencing new table as new_table
for each statement
execute function create_workflow_run_concurrency_groups_on_run_creation();

create trigger trigger_update_workflow_run_concurrency_groups_on_run_completion
after update on workflow_run
referencing old table as old_table new table as new_table
for each statement
execute function update_workflow_run_concurrency_groups_on_run_completion();