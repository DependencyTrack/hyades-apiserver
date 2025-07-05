# api

Definition of Dependency-Track's REST API, in [OpenAPI v3.0] format.

The API draws inspiration from [Zalando's RESTful API Guidelines].

Conformance to API guidelines is enforced with [spectral] in CI.  
Validation may be performed locally using [`openapi-lint.sh`](../dev/scripts/openapi-lint.sh).

Interfaces and model classes are generated as part of the build using [openapi-generator].

[OpenAPI v3.0]: https://spec.openapis.org/oas/v3.0.3.html
[Zalando's RESTful API Guidelines]: https://opensource.zalando.com/restful-api-guidelines/
[openapi-generator]: https://github.com/OpenAPITools/openapi-generator
[spectral]: https://github.com/stoplightio/spectral