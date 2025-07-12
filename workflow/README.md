# workflow

Embedded durable execution ("workflows-as-code") engine, optimized for PostgreSQL.

Heavily influenced by Microsoft's [Durable Task Framework](https://github.com/Azure/durabletask)
and [Temporal](https://github.com/temporalio/temporal).

## Structure

* [`api`](api) contains the public API for authoring durable workflows.
* [`engine-api`](engine-api) contains the public API for interacting with the engine.
* [`engine`](engine) contains the actual engine implementation.

`api` and `engine-api` have been separated from the core engine to make the respective
API surfaces more obvious, and prevent internals from leaking into the API. 
It is not intended that there exist other API implementations outside of `engine`.

The [Java module system](https://dev.java/learn/modules/intro/) is used to enforce strong encapsulation.
