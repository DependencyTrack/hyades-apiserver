# Design

## Core Decisions

### Embedded

Not requiring an external service simplifies operations due to fewer moving parts.
Testing and debugging becomes easier for the same reason.

Embedding the engine in the application further avoids network and serialization
overhead during task distribution, since workers can poll the database directly.

### PostgreSQL Only

Following the direction of the main Dependency-Track application, dex only supports PostgreSQL.
This allows for more optimization techniques, easier testing / debugging, and less operational
overhead for users.

### Buffering / Batching

In contrast to most other durable execution and workflow engines, dex buffers certain write
operations, and flushes them to the database in batches. This is done to reduce network round-trips
between dex and its database, as well as to amortize transaction overhead.

A property that all durable execution engines share, is that there is always a time window
between an action (e.g., issuing a HTTP request) having been *performed*, and its outcome having
been *recorded* (e.g., by writing it to a database). If recording the outcome fails,
the engine has to assume that the action itself has never happened. There is no way to make this atomic.
This is one reason why actions should be idempotent, making them safe to execute multiple times.
dex takes advantage of this inherent risk, and utilises buffering in exactly that time window.

When flushing buffers, dex leverages
[Postgres-specific optimizations](https://www.tigerdata.com/blog/boosting-postgres-insert-performance)
to further reduce the amount of time spent *in the database*.

> [!NOTE]
> This is a trade-off that values throughput over latency, and efficiency over correctness:
> * While throughput is improved, buffering *does* negatively impact end-to-end latency.
> * Flushing writes in batches comes with the risk of an increased blast radius in case of failures.

Dependency-Track is not a latency-sensitive system. It is generally acceptable to wait
a few seconds for a workflow to complete. It is much more important that the database is
not hammered with many tiny transactions that spike CPU and I/O utilization.

> [!NOTE]
> Intervals of pollers and buffer flushes are configurable. Users who care more about latency
> are free to decrease intervals, at the cost of higher database utilization.

PostgreSQL is not infinitely scalable, but by designing a system optimized for throughput
and efficiency, our scaling ceiling is much higher.

### No `LISTEN` / `NOTIFY`

Many queueing systems based on PostgreSQL utilize the [`LISTEN` / `NOTIFY`](https://www.postgresql.org/docs/current/sql-notify.html)
feature to reduce latencies, e.g. by emitting a notification whenever a new task has been scheduled for execution.

This was explored for dex as well, but ultimately discarded, because:

* `LISTEN` requires a persistent, direct connection to the database, which does not play well with connection poolers.
* > When a NOTIFY query is issued during a transaction, it acquires a global lock on the entire database
  > [...] during the commit phase of the transaction, effectively serializing all commits.
  > ([Source](https://www.recall.ai/blog/postgres-listen-notify-does-not-scale))

Instead, dex entirely relies on polling.

### Protobuf Serialization

Workflow events, as well as workflow and activity arguments and results, leverage Protobuf for serialization.
Protobuf is fast and efficient, and serialized messages are smaller than their JSON counterparts.

The tooling around Protobuf is excellent. With [`buf`](https://buf.build/), we have linting and breaking
change detection covered. 

This decision comes with the drawback of events and payloads not being human-readable when
manually inspecting database tables.

### Virtual Threads

Workers leverage [virtual threads](https://docs.oracle.com/en/java/javase/21/core/virtual-threads.html)
for task execution. This enables higher degrees of concurrency while keeping resource footprint low.
Worker concurrency is still constrained (using Semaphores), but it's not necessary to maintain pools of
heavyweight platform threads.

## Leader Election

Certain operations are intended to only be performed by a single node in a cluster. For example:

* Task scheduling
* Retention enforcement

dex utilises a simple lease-based leader election mechanism that is backed
by the `dex_lease` table with the following schema:

| Column      | Type           | Constraints |
|:------------|:---------------|:------------|
| name        | text           | pk          |
| acquired_by | text           | not null    |
| acquired_at | timestamptz(3) | not null    |
| expires_at  | timestamptz(3) | not null    |

Every node in the cluster will regularly (default: 15s) try to acquire the leadership lease
for a given period of time (default: 30s).

A lease is acquired by inserting into the `dex_lease` table. Concurrency-safe conflict
resolution is performed using PostgreSQL's `insert into ... on conflict do update` mechanism:

```sql
insert into dex_lease (name, acquired_by, acquired_at, expires_at)
values ('leadership', 'instanceA', now(), now() + interval '30 seconds')
on conflict (name) do update
set acquired_by = excluded.acquired_by
  , acquired_at = excluded.acquired_at
  , expires_at = excluded.expires_at
where dex_lease.acquired_by = excluded.acquired_by
   or dex_lease.expires_at <= now()
```

The above query atomically creates or extends the lease for `instanceA`,
depending on whether the lease is still held by it, or the previous lease
has expired.

Nodes that fail to attempt lease acquisition, e.g. due to timeouts,
will assume their lease to be *lost*. This is to prevent the likelihood
of [split-brain](https://en.wikipedia.org/wiki/Split-brain_(computing)).
It should be noted though that the worst symptom of split-brain for dex
is an increase is potentially expensive operations. Correctness is not affected.

During graceful shutdown, nodes simply release their leadership lease:

```sql
delete
  from dex_lease
 where name = 'leadership'
   and acquired_by = 'instanceA'
```

The `dex_lease` table is [`unlogged`](https://www.postgresql.org/docs/current/sql-createtable.html#SQL-CREATETABLE-UNLOGGED)
and thus does not cause WAL writes. This is possible because leases are ephemeral by design.