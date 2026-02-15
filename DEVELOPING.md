# Developing

> Please also read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## Prerequisites

* JDK 21+ ([Temurin](https://adoptium.net/temurin/releases) distribution recommended)
* Maven 3.9+
* Docker or Podman (required for [tests](#testing) and [dev mode](#dev-mode))
* A Java IDE (IntelliJ recommended)

> [!TIP]
> We recommend [sdkman](https://sdkman.io/) for managing JDK and Maven installations,
> and [mvnd](https://github.com/apache/maven-mvnd) for faster builds.
> The `Makefile` automatically uses `mvnd` when available, falling back to `mvn`.

> [!NOTE]
> This guide uses [`make`](https://www.gnu.org/software/make/) commands for brevity,
> and we recommend that you use `make` if you prefer CLI-centric workflows.
> If using `make` is not an option, you can inspect the full commands in [`Makefile`](Makefile)
> and use them for your own custom workflows.
> 
> For IDE-centric workflows, we provide equivalent IntelliJ [run configurations](.idea/runConfigurations).

## Core Technologies

| Technology                                                                                  | Purpose                   |
|:--------------------------------------------------------------------------------------------|:--------------------------|
| [Jakarta REST (JAX-RS)](https://projects.eclipse.org/projects/ee4j.rest)                    | REST API specification    |
| [Jersey](https://eclipse-ee4j.github.io/jersey/)                                            | JAX-RS implementation     |
| [OpenAPI](https://www.openapis.org/)                                                        | API specification         |
| [JDO](https://db.apache.org/jdo/)                                                           | Persistence specification |
| [DataNucleus](https://www.datanucleus.org/products/accessplatform/jdo/getting_started.html) | JDO implementation        |
| [JDBI](https://jdbi.org/)                                                                   | Database access           |
| [Liquibase](https://www.liquibase.com/)                                                     | Database migrations       |
| [MicroProfile Config](https://microprofile.io/specifications/microprofile-config/)          | Configuration             |
| [Jetty](https://www.eclipse.org/jetty/)                                                     | Servlet container         |
| [Apache Kafka](https://kafka.apache.org/)                                                   | Event streaming           |
| [PostgreSQL](https://www.postgresql.org/)                                                   | Database                  |
| [Testcontainers](https://testcontainers.com/)                                               | Integration testing       |
| [Protocol Buffers](https://protobuf.dev/)                                                   | Serialization             |

> [!NOTE]
> We're currently in the process of phasing out Kafka.

## Building

Build the project:

```shell
make build
```

> [!TIP]
> (Re-) building the entire project via `make build` is cheap due to [build caching](#build-cache).
> You generally don't need to build modules selectively.

The resulting JAR is placed in `./apiserver/target` as `dependency-track-apiserver.jar`.
It ships with an embedded Jetty server, there's no need to deploy it in an application
server like Tomcat or WildFly.

Build a container image:

```shell
make build-image
```

This produces the image `ghcr.io/dependencytrack/hyades-apiserver:local`.

## Testing

Run all tests:

```shell
make test
```

Run a single test class:

```shell
make test-single MODULE=apiserver TEST=FooTest
```

Run multiple test classes:

```shell
make test-single MODULE=apiserver TEST="FooTest,BarTest"
```

Run a single test method:

```shell
make test-single MODULE=apiserver TEST="FooTest#testFoo"
```

## Dev Mode

Dev mode launches the API server with auto-provisioned containers for PostgreSQL, Kafka,
and the frontend. Containers are created on startup and disposed of on shutdown.

```shell
make apiserver-dev
```

The API server will be available at `http://localhost:8080`.
Frontend, Kafka, and PostgreSQL ports are logged during startup.

Dev mode specific configuration can be made in [`application-dev.properties`](apiserver/src/main/resources/application-dev.properties).

## DataNucleus Bytecode Enhancement

Classes annotated with `@PersistenceCapable` must be
[enhanced](https://www.datanucleus.org/products/accessplatform/jdo/enhancer.html)
post-compilation. Maven handles this automatically, but IDEs run their own builds
and may skip the enhancement step.

If you see `NucleusUserException: Found Meta-Data for class ... but this class is either not enhanced`
when running tests from your IDE, run:

```shell
make datanucleus-enhance
```

Then re-run the test. Ensure your IDE is not cleaning the `target` directory before execution.

## Build Cache

We use Maven [build caching](https://maven.apache.org/extensions/maven-build-cache-extension/) to speed
up builds. If you encounter stale or unexplainable build issues, try clearing the cache and see if it
resolves your issues:

```shell
make clean-build-cache
```
