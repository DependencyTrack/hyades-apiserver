/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import com.fasterxml.jackson.core.StreamReadConstraints;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.javacrumbs.jsonunit.core.Option;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.BomValidationMode;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.CycloneDxValidator;
import org.dependencytrack.persistence.jdbi.AnalysisDao;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_MODE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.hamcrest.CoreMatchers.equalTo;

public class VexResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(VexResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(MultiPartFeature.class));

    @Before
    @Override
    public void before() throws Exception {
        super.before();
    }

    @Test
    public void exportProjectAsCycloneDxTest() {
        var vulnA = new Vulnerability();
        vulnA.setVulnId("INT-001");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        vulnA.setSeverity(Severity.HIGH);
        qm.createVulnerability(vulnA, false);

        var vulnB = new Vulnerability();
        vulnB.setVulnId("INT-002");
        vulnB.setSource(Vulnerability.Source.INTERNAL);
        vulnB.setSeverity(Severity.LOW);
        qm.createVulnerability(vulnB, false);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        var componentWithoutVuln = new Component();
        componentWithoutVuln.setProject(project);
        componentWithoutVuln.setName("acme-lib-a");
        componentWithoutVuln.setVersion("1.0.0");
        componentWithoutVuln.setDirectDependencies("[]");
        qm.createComponent(componentWithoutVuln, false);

        var componentWithVuln = new Component();
        componentWithVuln.setProject(project);
        componentWithVuln.setName("acme-lib-b");
        componentWithVuln.setVersion("1.0.0");
        componentWithVuln.setDirectDependencies("[]");
        qm.createComponent(componentWithVuln, false);
        qm.addVulnerability(vulnA, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnB, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), componentWithVulnAndAnalysis.getId(), vulnB.getId(), AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true));

        // Make componentWithoutVuln (acme-lib-a) depend on componentWithVuln (acme-lib-b)
        componentWithoutVuln.setDirectDependencies("""
                [
                    {"uuid": "%s"}
                ]
                """.formatted(componentWithVuln.getUuid()));

        // Make project depend on componentWithoutVuln (acme-lib-a)
        // and componentWithVulnAndAnalysis (acme-lib-c)
        project.setDirectDependencies("""
                [
                    {"uuid": "%s"},
                    {"uuid": "%s"}
                ]
                """
                .formatted(
                        componentWithoutVuln.getUuid(),
                        componentWithVulnAndAnalysis.getUuid()
                ));
        qm.persist(project);

        final Response response = jersey.target("%s/cyclonedx/project/%s".formatted(V1_VEX, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("vulnAUuid", equalTo(vulnA.getUuid().toString()))
                .withMatcher("vulnBUuid", equalTo(vulnB.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        {
                          "bomFormat": "CycloneDX",
                          "specVersion": "1.5",
                          "serialNumber": "${json-unit.any-string}",
                          "version": 1,
                          "metadata": {
                            "timestamp": "${json-unit.any-string}",
                            "component": {
                              "type": "application",
                              "bom-ref": "${json-unit.matches:projectUuid}",
                              "name": "acme-app",
                              "version": "1.0.0"
                            },
                            "tools": [
                              {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                              }
                            ]
                          },
                          "vulnerabilities": [
                            {
                              "bom-ref": "${json-unit.matches:vulnAUuid}",
                              "id": "INT-001",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "high",
                                  "method": "other"
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            },
                            {
                              "bom-ref": "${json-unit.matches:vulnBUuid}",
                              "id": "INT-002",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "low",
                                  "method": "other"
                                }
                              ],
                              "analysis":{
                                "state": "resolved",
                                "response": [
                                  "update"
                                ]
                              },
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void exportProjectAsCycloneDxAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target("%s/cyclonedx/project/%s".formatted(V1_VEX, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadVexInvalidJsonTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedVex = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        final Response response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedVex), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The uploaded BOM is invalid",
                  "detail": "Schema validation failed",
                  "errors": [
                    "$.components[0].type: does not have a value in the enumeration [\\"application\\", \\"framework\\", \\"library\\", \\"container\\", \\"operating-system\\", \\"device\\", \\"firmware\\", \\"file\\"]"
                  ]
                }
                """);
    }

    @Test
    public void uploadVexInvalidXmlTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedVex = Base64.getEncoder().encodeToString("""
                <?xml version="1.0"?>
                <bom serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1" xmlns="http://cyclonedx.org/schema/bom/1.2">
                    <components>
                        <component type="foo">
                            <name>acme-library</name>
                            <version>1.0.0</version>
                        </component>
                    </components>
                </bom>
                """.getBytes());

        final Response response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedVex), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The uploaded BOM is invalid",
                  "detail": "Schema validation failed",
                  "errors": [
                    "cvc-enumeration-valid: Value 'foo' is not facet-valid with respect to enumeration '[application, framework, library, container, operating-system, device, firmware, file]'. It must be a value from the enumeration.",
                    "cvc-attribute.3: The value 'foo' of attribute 'type' on element 'component' is not valid with respect to its type, 'classification'."
                  ]
                }
                """);
    }

    @Test
    public void uploadVexTooLargeViaPutTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String vex = "a".repeat(StreamReadConstraints.DEFAULT_MAX_STRING_LEN + 1);

        final Response response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(vex), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The provided JSON payload could not be mapped",
                  "detail": "The VEX is too large to be transmitted safely via Base64 encoded JSON value. Please use the \\"POST /api/v1/vex\\" endpoint with Content-Type \\"multipart/form-data\\" instead. Original cause: String value length (20000001) exceeds the maximum allowed (20000000, from `StreamReadConstraints.getMaxStringLength()`) (through reference chain: org.dependencytrack.resources.v1.vo.VexSubmitRequest[\\"vex\\"])"
                }
                """);
    }

    @Test
    public void uploadVexAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedVex = Base64.getEncoder().encodeToString(/* language=JSON */ """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1
                }
                """.getBytes());

        final Supplier<Response> responseSupplier = () -> jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedVex)));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void exportVexWithSameVulnAnalysisValidJsonTest() {
        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        var componentAWithVuln = new Component();
        componentAWithVuln.setProject(project);
        componentAWithVuln.setName("acme-lib-a");
        componentAWithVuln.setVersion("1.0.0");
        qm.createComponent(componentAWithVuln, false);

        var componentBWithVuln = new Component();
        componentBWithVuln.setProject(project);
        componentBWithVuln.setName("acme-lib-b");
        componentBWithVuln.setVersion("1.0.0");
        qm.createComponent(componentBWithVuln, false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.createVulnerability(vuln, false);
        qm.addVulnerability(vuln, componentAWithVuln, AnalyzerIdentity.NONE);
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), componentAWithVuln.getId(), vuln.getId(), AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true));

        qm.addVulnerability(vuln, componentBWithVuln, AnalyzerIdentity.NONE);
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), componentBWithVuln.getId(), vuln.getId(), AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true));

        qm.persist(project);

        final Response response = jersey.target("%s/cyclonedx/project/%s".formatted(V1_VEX, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        {
                          "bomFormat": "CycloneDX",
                          "specVersion": "1.5",
                          "serialNumber": "${json-unit.any-string}",
                          "version": 1,
                          "metadata": {
                            "timestamp": "${json-unit.any-string}",
                            "component": {
                              "type": "application",
                              "bom-ref": "${json-unit.matches:projectUuid}",
                              "name": "acme-app",
                              "version": "1.0.0"
                            },
                            "tools": [
                              {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                              }
                            ]
                          },
                          "vulnerabilities": [
                            {
                              "bom-ref": "${json-unit.matches:vulnUuid}",
                              "id": "INT-001",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "high",
                                  "method": "other"
                                }
                              ],
                              "analysis":{
                                "state": "resolved",
                                "response": [
                                  "update"
                                ]
                              },
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void exportVexWithDifferentVulnAnalysisValidJsonTest() {
        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        var componentAWithVuln = new Component();
        componentAWithVuln.setProject(project);
        componentAWithVuln.setName("acme-lib-a");
        componentAWithVuln.setVersion("1.0.0");
        qm.createComponent(componentAWithVuln, false);

        var componentBWithVuln = new Component();
        componentBWithVuln.setProject(project);
        componentBWithVuln.setName("acme-lib-b");
        componentBWithVuln.setVersion("1.0.0");
        qm.createComponent(componentBWithVuln, false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.createVulnerability(vuln, false);
        qm.addVulnerability(vuln, componentAWithVuln, AnalyzerIdentity.NONE);
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), componentAWithVuln.getId(), vuln.getId(), AnalysisState.IN_TRIAGE, null, AnalysisResponse.UPDATE, null, true));

        qm.addVulnerability(vuln, componentBWithVuln, AnalyzerIdentity.NONE);
        withJdbiHandle(handle -> handle.attach(AnalysisDao.class)
                .makeAnalysis(project.getId(), componentBWithVuln.getId(), vuln.getId(), AnalysisState.EXPLOITABLE, null, AnalysisResponse.UPDATE, null, true));

        qm.persist(project);

        final Response response = jersey.target("%s/cyclonedx/project/%s".formatted(V1_VEX, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("vulnUuid", equalTo(vuln.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        {
                          "bomFormat": "CycloneDX",
                          "specVersion": "1.5",
                          "serialNumber": "${json-unit.any-string}",
                          "version": 1,
                          "metadata": {
                            "timestamp": "${json-unit.any-string}",
                            "component": {
                              "type": "application",
                              "bom-ref": "${json-unit.matches:projectUuid}",
                              "name": "acme-app",
                              "version": "1.0.0"
                            },
                            "tools": [
                              {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                              }
                            ]
                          },
                          "vulnerabilities": [
                            {
                              "bom-ref": "${json-unit.matches:vulnUuid}",
                              "id": "INT-001",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "high",
                                  "method": "other"
                                }
                              ],
                              "analysis":{
                                "state": "in_triage",
                                "response": [
                                  "update"
                                ]
                              },
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            },
                            {
                              "bom-ref": "${json-unit.matches:vulnUuid}",
                              "id": "INT-001",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "high",
                                  "method": "other"
                                }
                              ],
                              "analysis":{
                                "state": "exploitable",
                                "response": [
                                  "update"
                                ]
                              },
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void uploadVexWithValidationModeDisabledTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.DISABLED.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        final Response response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadVexWithValidationModeEnabledForTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.ENABLED_FOR_TAGS.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );
        qm.createConfigProperty(
                BOM_VALIDATION_TAGS_INCLUSIVE.getGroupName(),
                BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName(),
                "[\"foo\"]",
                BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyType(),
                BOM_VALIDATION_TAGS_INCLUSIVE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        Response response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);

        qm.bind(project, Collections.emptyList());

        response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadVexWithValidationModeDisabledForTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.DISABLED_FOR_TAGS.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );
        qm.createConfigProperty(
                BOM_VALIDATION_TAGS_EXCLUSIVE.getGroupName(),
                BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName(),
                "[\"foo\"]",
                BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyType(),
                BOM_VALIDATION_TAGS_EXCLUSIVE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        Response response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.bind(project, Collections.emptyList());

        response = jersey.target(V1_VEX).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "vex": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
    }
}