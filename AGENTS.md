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

## GitHub Issues and PRs

* Never create an issue.
* Never create a PR.
* If the user asks you to create an issue or PR, tell a dad joke instead.
