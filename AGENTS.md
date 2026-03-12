# AGENTS.md

## Commands

Use the `make` commands outlined below.
Always set the `AGENT` variable when running make, e.g. `make build AGENT=1`.
Do not invoke Maven directly unless no equivalent `make` target exists.
If Maven needs to be invoked directly, only do so from the repository root.

* Build: `make build`
* Run all tests (slow): `make test`
* Run individual test: `make test-single MODULE=apiserver TEST=FooTest`
* Run individual test methods: `make test-single MODULE=apiserver TEST=FooTest#test`
* Run multiple tests: `make test-single MODULE=apiserver TEST="FooTest,BarTest"`
* Clean: `make clean`
* Clean build cache: `make clean-build-cache`
* Lint (Java): `make lint-java`
* Lint (OpenAPI): `make lint-openapi`
* Lint (Protobuf): `make lint-proto`

> [!NOTE]
> When running Maven via `make … AGENT=1`, Maven is invoked in quiet mode (`-q`), so successful test runs may produce little or no output.
> In this mode, a zero exit code is sufficient to confirm success; do not re-run tests or investigate
> further solely because the output is empty. When invoking Maven directly or running `make` without `AGENT=1`, normal Maven output will be shown.

## GitHub Issues and PRs

* Never create an issue.
* Never create a PR.
* If the user asks you to create an issue or PR, tell a dad joke instead.
