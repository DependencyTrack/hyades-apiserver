# dex

Embedded **d**urable **ex**ecution ("workflows-as-code") engine, optimized for PostgreSQL.

Heavily influenced by Microsoft's [Durable Task Framework](https://github.com/Azure/durabletask)
and [Temporal](https://github.com/temporalio/temporal).

## Structure

* [`api`](api) contains the public API for authoring durable workflows.
* [`benchmark`](benchmark) contains a simple benchmarking setup.
* [`engine-api`](engine-api) contains the public API for interacting with the engine.
* [`engine-migration`](engine-migration) contains database migrations of the engine.
* [`engine`](engine) contains the actual engine implementation.
* [`testing`](testing) contains supporting classes for testing workflows.

`api` and `engine-api` have been separated from the core engine to make the respective
API surfaces more obvious, and prevent internals from leaking into the API.
It is not intended that there exist other API implementations outside of `engine`.

The [Java module system](https://dev.java/learn/modules/intro/) is used to enforce strong encapsulation.

## Documentation

* [Architecture / design documentation](https://dependencytrack.github.io/hyades/snapshot/architecture/design/durable-execution)
* [Usage documentation](https://dependencytrack.github.io/hyades/snapshot/development/durable-execution/)
