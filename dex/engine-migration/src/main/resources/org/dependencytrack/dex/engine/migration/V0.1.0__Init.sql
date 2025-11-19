create type dex_workflow_run_status as enum (
  'CREATED'
, 'RUNNING'
, 'SUSPENDED'
, 'CANCELED'
, 'COMPLETED'
, 'FAILED'
);

create table dex_workflow_task_queue (
  name text
, partition_name text not null
, status text not null default 'ACTIVE'
, max_concurrency smallint not null default 100
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint dex_workflow_task_queue_pk primary key (name)
, constraint dex_activity_task_queue_status_check CHECK (status in ('ACTIVE', 'PAUSED'))
);

create table dex_workflow_run (
  id uuid
, parent_id uuid
, workflow_name text not null
, workflow_version smallint not null
, queue_name text not null
, status dex_workflow_run_status not null default 'CREATED'
, custom_status text
, concurrency_group_id text
, priority smallint not null default 0
, labels jsonb
, created_at timestamptz(3) not null
, updated_at timestamptz(3)
, started_at timestamptz(3)
, completed_at timestamptz(3)
, constraint dex_workflow_run_pk primary key (id)
, constraint dex_workflow_run_parent_fk foreign key (parent_id) references dex_workflow_run (id) on delete cascade
, constraint dex_workflow_run_queue_fk foreign key (queue_name) references dex_workflow_task_queue (name) on delete cascade
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 80);

create table dex_workflow_task (
  queue_name text
, workflow_run_id uuid
, workflow_name text not null
, priority smallint not null
, locked_by text
, locked_until timestamptz(3)
, created_at timestamptz(3) not null default now()
, constraint dex_workflow_task_pk primary key (queue_name, workflow_run_id)
, constraint dex_workflow_task_queue_fk foreign key (queue_name) references dex_workflow_task_queue (name) on delete cascade
, constraint dex_workflow_task_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade
) partition by list (queue_name);

create table dex_workflow_run_concurrency_group (
  id text
, next_run_id uuid not null
, constraint dex_workflow_run_concurrency_group_pk primary key (id)
, constraint dex_workflow_run_concurrency_group_next_run_fk foreign key (next_run_id) references dex_workflow_run (id) on delete cascade
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 90);

create table dex_workflow_run_history (
  workflow_run_id uuid
, sequence_number int
, event bytea not null
, constraint dex_workflow_run_history_pk primary key (workflow_run_id, sequence_number)
, constraint dex_workflow_run_history_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade
) partition by hash (workflow_run_id);

create table dex_workflow_run_history_p00 partition of dex_workflow_run_history for values with (modulus 8, remainder 0);
create table dex_workflow_run_history_p01 partition of dex_workflow_run_history for values with (modulus 8, remainder 1);
create table dex_workflow_run_history_p02 partition of dex_workflow_run_history for values with (modulus 8, remainder 2);
create table dex_workflow_run_history_p03 partition of dex_workflow_run_history for values with (modulus 8, remainder 3);
create table dex_workflow_run_history_p04 partition of dex_workflow_run_history for values with (modulus 8, remainder 4);
create table dex_workflow_run_history_p05 partition of dex_workflow_run_history for values with (modulus 8, remainder 5);
create table dex_workflow_run_history_p06 partition of dex_workflow_run_history for values with (modulus 8, remainder 6);
create table dex_workflow_run_history_p07 partition of dex_workflow_run_history for values with (modulus 8, remainder 7);

create table dex_workflow_run_inbox (
  id bigint generated always as identity
, workflow_run_id uuid not null
, visible_from timestamptz(3)
, locked_by text
, dequeue_count smallint
, event bytea not null
, constraint dex_workflow_run_inbox_pk primary key (id)
) with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 80);

create table dex_activity_task_queue (
  name text
, partition_name text not null
, status text not null default 'ACTIVE'
, max_concurrency smallint not null default 100
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint dex_activity_task_queue_pk primary key (name)
, constraint dex_activity_task_queue_status_check CHECK (status in ('ACTIVE', 'PAUSED'))
);

create table dex_activity_task (
  queue_name text not null
, workflow_run_id uuid
, created_event_id int
, activity_name text not null
, priority smallint not null default 0
, status text not null default 'CREATED'
, argument bytea
, visible_from timestamptz(3)
, locked_by text
, locked_until timestamptz(3)
, created_at timestamptz(3) not null default now()
, updated_at timestamptz(3)
, constraint dex_activity_task_pk primary key (queue_name, workflow_run_id, created_event_id)
, constraint dex_activity_task_workflow_run_fk foreign key (workflow_run_id) references dex_workflow_run (id) on delete cascade
, constraint dex_activity_task_queue_fk foreign key (queue_name) references dex_activity_task_queue (name)
, constraint dex_activity_task_status_check check (status in ('CREATED', 'QUEUED'))
) partition by list (queue_name);

-- Index to support polling of the workflow task scheduler.
create index dex_workflow_run_task_scheduler_poll_idx
    on dex_workflow_run (priority desc, id)
 where status = any(cast('{CREATED, RUNNING, SUSPENDED}' as dex_workflow_run_status[]));

-- Index to support polling of workflow task workers.
create index dex_workflow_task_poll_idx
    on dex_workflow_task (priority desc, workflow_run_id);

create index dex_workflow_run_concurrency_group_update_idx
    on dex_workflow_run (concurrency_group_id, priority desc, id)
 where status = cast('CREATED' as dex_workflow_run_status)
   and concurrency_group_id is not null;

-- Index to support searching of workflow runs by label.
create index dex_workflow_run_labels_idx
    on dex_workflow_run using gin (labels jsonb_path_ops)
 where labels is not null;

create index dex_workflow_run_created_at_idx
    on dex_workflow_run (created_at);

-- Index to support retention enforcement of completed workflow runs.
create index dex_workflow_run_completed_at_idx
    on dex_workflow_run (completed_at)
 where completed_at is not null;

create index dex_workflow_run_inbox_workflow_run_id_idx
    on dex_workflow_run_inbox (workflow_run_id);

-- Index to support polling of activity task workers.
create index dex_activity_task_poll_idx
    on dex_activity_task (priority desc, created_at)
 where status = 'QUEUED';

create function dex_create_workflow_task_queue(queue_name text, max_queue_concurrency smallint)
returns bool as $$
declare
  normalized_queue_name text;
  partition_name text;
begin
  -- Ensure the name is OK to use for identifiers.
  select lower(regexp_replace(queue_name, '[^A-Za-z0-9_]', '_', 'g'))
    into normalized_queue_name;

  -- Ensure the partition name doesn't exceed the 63 characters limit.
  select format('dex_workflow_task_q_%s', left(normalized_queue_name, 43))
    into partition_name;

  execute format($q$
    create table %I partition of dex_workflow_task for values in (%L)
      with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 85);
  $q$, partition_name, queue_name);

  insert into dex_workflow_task_queue (name, partition_name, max_concurrency)
  values (queue_name, partition_name, max_queue_concurrency);

  return true;
end;
$$ language plpgsql;

create function dex_create_activity_task_queue(queue_name text, max_queue_concurrency smallint)
returns bool as $$
declare
  normalized_queue_name text;
  partition_name text;
begin
  -- Ensure the name is OK to use for identifiers.
  select lower(regexp_replace(queue_name, '[^A-Za-z0-9_]', '_', 'g'))
    into normalized_queue_name;

  -- Ensure the partition name doesn't exceed the 63 characters limit.
  select format('dex_activity_task_q_%s', left(normalized_queue_name, 43))
    into partition_name;

  execute format($q$
    create table %I partition of dex_activity_task for values in (%L)
      with (autovacuum_vacuum_scale_factor = 0.02, fillfactor = 85);
  $q$, partition_name, queue_name);

  insert into dex_activity_task_queue (name, partition_name, max_concurrency)
  values (queue_name, partition_name, max_queue_concurrency);

  return true;
end;
$$ language plpgsql;

create function dex_create_workflow_run_concurrency_groups_on_run_creation()
returns trigger
as $$
begin
  insert into dex_workflow_run_concurrency_group (id, next_run_id)
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

create function dex_update_workflow_run_concurrency_groups_on_run_completion()
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
   where old_table.status = any(cast('{CREATED, RUNNING, SUSPENDED}' as dex_workflow_run_status[]))
     and new_table.status = any(cast('{CANCELED, COMPLETED, FAILED}' as dex_workflow_run_status[]))
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
      from dex_workflow_run
     where concurrency_group_id = any(group_ids)
       and status = cast('CREATED' as dex_workflow_run_status)
     order by concurrency_group_id
            , priority desc
            , id
  ),
  cte_updated_group as (
    update dex_workflow_run_concurrency_group
       set next_run_id = cte_next_run.id
      from cte_next_run
     where dex_workflow_run_concurrency_group.id = cte_next_run.concurrency_group_id
    returning dex_workflow_run_concurrency_group.id
  )
  select array_agg(id)
    into updated_group_ids
    from cte_updated_group;

  if coalesce(array_length(updated_group_ids, 1), 0) = array_length(group_ids, 1) then
    return null;
  end if;

  -- Delete concurrency groups for which no next run could be determined.
  delete
    from dex_workflow_run_concurrency_group
   where id = any(group_ids)
     and id != all(updated_group_ids);

  return null;
end;
$$ language plpgsql;

create trigger trigger_dex_workflow_run_concurrency_groups_on_run_creation
after insert on dex_workflow_run
referencing new table as new_table
for each statement
execute function dex_create_workflow_run_concurrency_groups_on_run_creation();

create trigger trigger_dex_workflow_run_concurrency_groups_on_run_completion
after update on dex_workflow_run
referencing old table as old_table new table as new_table
for each statement
execute function dex_update_workflow_run_concurrency_groups_on_run_completion();