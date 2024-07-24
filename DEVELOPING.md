# Hacking on OWASP Dependency-Track

Want to hack on Dependency-Track? Awesome, here's what you need to know to get started!

> Please be sure to read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and
> [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) as well.

## Repositories

As of now, the Dependency-Track project consists of two separate repositories:

* [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) - The main application, also
  referred to as API server, based on Java and [Alpine](https://github.com/stevespringett/Alpine).
* [DependencyTrack/frontend](https://github.com/DependencyTrack/frontend) - The frontend, a single page application (
  SPA), based on JavaScript and [Vue](https://vuejs.org/).

This document primarily covers the API server. Please refer to the frontend repository for frontend-specific
instructions.

## Prerequisites

There are a few things you'll need on your journey:

* JDK 17+ ([Temurin](https://adoptium.net/temurin/releases) distribution recommended)
* Maven (comes bundled with IntelliJ and Eclipse)
* A Java IDE of your preference (we recommend IntelliJ, but any other IDE is fine as well)
* Docker (optional)

> We provide common [run configurations](https://www.jetbrains.com/help/idea/run-debug-configuration.html) for IntelliJ
> in the [`.idea/runConfigurations`](.idea/runConfigurations) directory for convenience. IntelliJ will automatically pick those up when you open this
> repository.

## Core Technologies

Knowing about the core technologies used by the API server may help you with understanding its codebase.

| Technology                                                                                      | Purpose                   |
|:------------------------------------------------------------------------------------------------|:--------------------------|
| [JAX-RS](https://projects.eclipse.org/projects/ee4j.rest)                                       | REST API specification    |
| [Jersey](https://eclipse-ee4j.github.io/jersey/)                                                | JAX-RS implementation     |
| [Java Data Objects (JDO)](https://db.apache.org/jdo/)                                           | Persistence specification |
| [DataNucleus](https://www.datanucleus.org/products/accessplatform/jdo/getting_started.html)     | JDO implementation        |
| [Jetty](https://www.eclipse.org/jetty/)                                                         | Servlet Container         |
| [Alpine](https://github.com/stevespringett/Alpine)                                              | Framework / Scaffolding   |

## Building

Build an executable JAR containing just the API server:

```shell
mvn clean package -P clean-exclude-wars -P enhance -P embedded-jetty -DskipTests -Dlogback.configuration.file=src/main/docker/logback.xml
```

The resulting file is placed in `./target` as `dependency-track-apiserver.jar`.
The JAR ships with 
an [embedded Jetty server](https://github.com/stevespringett/Alpine/tree/master/alpine-executable-war),
there's no need to deploy it in an application server like Tomcat or WildFly.

## Running

In case you want to provide a topic prefix to use in conjunction with hyades application then the environment variable
to export is DT_KAFKA_TOPIC_PREFIX<br/>
If the host environment requires ssl configuration then below configurations need to be passed:

| Environment Variable                    | Description                              | Default | Required |
|:----------------------------------------|:-----------------------------------------|:--------|:--------:|
| `DT_KAFKA_TOPIC_PREFIX`                 | Prefix for topic names                   | -       |    ✅     |
| `KAFKA_TLS_ENABLED`                     | Whether tls is enabled                   | false   |    ❌     |
| `KAFKA_SECURTY_PROTOCOL`                | Security protocol to be used             | -       |    ❌     |
| `KAFKA_TRUSTSTORE_PATH`                 | Trust store path to be used              | -       |    ❌     |
| `KAFKA_TRUSTSTORE_PASSWORD`             | Trust store password                     | -       |    ❌     |
| `KAFKA_MTLS_ENABLED`                    | Whether mtls is enabled                  | false   |    ❌     |
| `KAFKA_KEYSTORE_PATH`                   | Key store path to be used                | -       |    ❌     |
| `KAFKA_KEYSTORE_PASSWORD`               | Key store password                       | -       |    ❌     |
| `KAFKA_STREAMS_METRICS_RECORDING_LEVEL` | Recording level of Kafka Streams metrics | `INFO`  |    ❌     |

(If tls is enabled then the security protocol, truststore path and password would be required properties)
(If mtls is enabled then additional to truststore, keystore path and password would be required properties)

To run a previously built executable JAR, just invoke it with `java -jar`, e.g.:

```shell
java -jar ./target/dependency-track-apiserver.jar
```

The API server will be available at `http://127.0.0.1:8080`.

Additional configuration (e.g. database connection details) can be provided as usual via `application.properties`
or environment variables. Refer to
the [configuration documentation](https://docs.dependencytrack.org/getting-started/configuration/).

## Debugging

To build and run the API server in one go, invoke the Jetty Maven plugin as follows:

```shell
mvn jetty:run -P enhance -Dlogback.configurationFile=src/main/docker/logback.xml
```

The above command is also suitable for debugging. For IntelliJ, simply *Debug* the [Jetty](.idea/runConfigurations/Jetty.run.xml) run
configuration.

## Debugging with Frontend

Start the API server via the Jetty Maven plugin (see [Debugging](#debugging) above). The API server will listen on
`http://127.0.0.1:8080`.

Clone the frontend repository, install its required dependencies and launch the Vue development server:

```shell
git clone https://github.com/DependencyTrack/frontend.git dependency-track-frontend
cd ./dependency-track-frontend
npm ci
npm run serve
```

Per default, the Vue development server will listen on port `8080`. If that port is taken, it will choose a higher,
unused port (typically `8081`). Due to this behavior, it is important to always start the API server first, unless
you want to fiddle with default configurations of both API server and frontend.

Now visit `http://127.0.0.1:8081` in your browser and use Dependency-Track as usual.

## Testing

To run all tests:

```shell
mvn clean verify -P enhance
```

Depending on your machine, this will take roughly 10-30min. Unless you modified central parts of the application,
starting single tests separately via IDE is a better choice.

## DataNucleus Bytecode Enhancement

Occasionally when running tests without Maven from within your IDE, you will run into failures due to exceptions
similar to this one:

```
org.datanucleus.exceptions.NucleusUserException: Found Meta-Data for class org.dependencytrack.model.Component but this class is either not enhanced or you have multiple copies of the persistence API jar in your CLASSPATH!! Make sure all persistable classes are enhanced before running DataNucleus and/or the CLASSPATH is correct.
```

This happens because DataNucleus requires classes annotated with `@PersistenceCapable` to
be [enhanced](https://www.datanucleus.org/products/accessplatform/jdo/enhancer.html).
Enhancement is performed on compiled bytecode and thus has to be performed post-compilation
(`process-classes` [lifecycle phase](https://maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html#Lifecycle_Reference)
in Maven).
During a Maven build,
the [DataNucleus Maven plugin](https://www.datanucleus.org/products/accessplatform/jdo/enhancer.html#maven)
takes care of this (that's also why `-P enhance` is required in all Maven commands).

Because most IDEs run their own build when executing tests, effectively bypassing Maven, bytecode enhancement is not
performed, and exceptions as that shown above are raised. If this happens, you can manually kick off the bytecode
enhancement like this:

```shell
mvn clean process-classes -P enhance
```

Now just execute the test again, and it should just work.

> If you're still running into issues, ensure that your IDE is not cleaning the workspace
> (removing the `target` directory) before executing the test.

## Building Container Images

Ensure you've built the API server JAR.

To build the API server image:

```shell
docker build --build-arg WAR_FILENAME=dependency-track-apiserver.jar -t dependencytrack/apiserver:local -f ./src/main/docker/Dockerfile .
```

## Shedlock 
Shedlock is being used to ensure that scheduled tasks are executed at most once at the same time. 
If a task is being executed on one node, it acquires a lock which prevents execution of the same task from another node (or thread). 
Please note, that if one task is already being executed on one node, execution on other nodes does not wait, it is simply skipped.

Lock can be configured using 2 properties:
lockAtMostFor - specifies how long the lock should be kept in case the executing node dies. 
                This is just a fallback, under normal circumstances the lock is released as soon the tasks finishes. 
                Set lockAtMostFor to a value which is much longer than normal execution time. 

lockAtLeastFor - specifies minimum amount of time for which the lock should be kept.
                  Its main purpose is to prevent execution from multiple nodes in case of really short tasks and clock difference between the nodes.

e.g. For lock held by Portfolio Metrics task, the above properties will be configured
task.metrics.portfolio.lockAtMostForInMillis



