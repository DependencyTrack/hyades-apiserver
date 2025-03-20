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

import alpine.common.util.UuidUtil;
import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import com.fasterxml.jackson.core.StreamReadConstraints;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import net.javacrumbs.jsonunit.core.Option;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.cyclonedx.proto.v1_6.Bom;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.BomValidationMode;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.parser.cyclonedx.CycloneDxValidator;
import org.dependencytrack.proto.notification.v1.BomValidationFailedSubject;
import org.dependencytrack.resources.v1.vo.BomSubmitRequest;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.runner.RunWith;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.json;
import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.apache.commons.io.IOUtils.resourceToString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_MODE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE;
import static org.dependencytrack.proto.notification.v1.Group.GROUP_BOM_VALIDATION_FAILED;
import static org.dependencytrack.proto.notification.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.util.KafkaTestUtil.deserializeValue;
import static org.hamcrest.CoreMatchers.equalTo;

@RunWith(JUnitParamsRunner.class)
public class BomResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(BomResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(MultiPartFeature.class));

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables()
            .set("FILE_STORAGE_EXTENSION_MEMORY_ENABLED", "true")
            .set("FILE_STORAGE_DEFAULT_EXTENSION", "memory");

    @Before
    @Override
    public void before() throws Exception {
        super.before();
    }

    @Test
    public void exportProjectAsCycloneDxTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        Component component = qm.createComponent(c, false);
        Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertTrue(body.startsWith("{"));
    }

    @Test
    public void exportProjectAsCycloneDxInvalidTest() {
        Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void exportProjectAsCycloneDxAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "inventory")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    }

    @Test
    public void exportProjectAsCycloneDxInventoryTest() {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);

        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("projectManufacturer");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("projectSupplier");

        var project = new Project();
        project.setName("acme-app");
        project.setClassifier(Classifier.APPLICATION);
        project.setManufacturer(projectManufacturer);
        project.setSupplier(projectSupplier);
        List<OrganizationalContact> authors = new ArrayList<>();
        authors.add(new OrganizationalContact() {{
            setName("SampleAuthor");
        }});
        project.setAuthors(authors);
        project = qm.createProject(project, null, false);

        final var projectProperty = new ProjectProperty();
        projectProperty.setProject(project);
        projectProperty.setGroupName("foo");
        projectProperty.setPropertyName("bar");
        projectProperty.setPropertyValue("baz");
        projectProperty.setPropertyType(IConfigProperty.PropertyType.STRING);
        qm.persist(projectProperty);

        final var bomSupplier = new OrganizationalEntity();
        bomSupplier.setName("bomSupplier");
        final var bomAuthor = new OrganizationalContact();
        bomAuthor.setName("bomAuthor");
        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setProject(project);
        projectMetadata.setAuthors(List.of(bomAuthor));
        projectMetadata.setSupplier(bomSupplier);
        qm.persist(projectMetadata);

        final var componentSupplier = new OrganizationalEntity();
        componentSupplier.setName("componentSupplier");
        var componentWithoutVuln = new Component();
        componentWithoutVuln.setProject(project);
        componentWithoutVuln.setName("acme-lib-a");
        componentWithoutVuln.setVersion("1.0.0");
        componentWithoutVuln.setSupplier(componentSupplier);
        componentWithoutVuln.setDirectDependencies("[]");
        componentWithoutVuln = qm.createComponent(componentWithoutVuln, false);

        // NB: Line, offset, and symbol are only supported since CycloneDX v1.6,
        // and will not show up in this export since it's still in v1.5 format.
        final var componentOccurrence = new ComponentOccurrence();
        componentOccurrence.setComponent(componentWithoutVuln);
        componentOccurrence.setLocation("/foo/bar");
        componentOccurrence.setLine(666);
        componentOccurrence.setOffset(123);
        componentOccurrence.setSymbol("someSymbol");
        qm.persist(componentOccurrence);

        final var componentProperty = new ComponentProperty();
        componentProperty.setComponent(componentWithoutVuln);
        componentProperty.setGroupName("foo");
        componentProperty.setPropertyName("bar");
        componentProperty.setPropertyValue("baz");
        componentProperty.setPropertyType(IConfigProperty.PropertyType.STRING);
        qm.persist(componentProperty);

        var componentWithVuln = new Component();
        componentWithVuln.setProject(project);
        componentWithVuln.setName("acme-lib-b");
        componentWithVuln.setVersion("1.0.0");
        componentWithVuln.setDirectDependencies("[]");
        componentWithVuln = qm.createComponent(componentWithVuln, false);
        qm.addVulnerability(vulnerability, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnerability, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnerability, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

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

        final Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "inventory")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentWithoutVulnUuid", equalTo(componentWithoutVuln.getUuid().toString()))
                .withMatcher("componentWithVulnUuid", equalTo(componentWithVuln.getUuid().toString()))
                .withMatcher("componentWithVulnAndAnalysisUuid", equalTo(componentWithVulnAndAnalysis.getUuid().toString()))
                .isEqualTo(json(/* language=JSON */ """
                        {
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.5",
                            "serialNumber": "${json-unit.ignore}",
                            "version": 1,
                            "metadata": {
                                "timestamp": "${json-unit.any-string}",
                                "authors": [
                                  {
                                     "name": "bomAuthor"
                                  }
                                ],
                                "component": {
                                    "type": "application",
                                    "bom-ref": "${json-unit.matches:projectUuid}",
                                    "author": "SampleAuthor",
                                    "supplier": {
                                      "name": "projectSupplier"
                                    },
                                    "name": "acme-app",
                                    "version": "SNAPSHOT"
                                },
                                "manufacture": {
                                  "name": "projectManufacturer"
                                },
                                "supplier": {
                                  "name": "bomSupplier"
                                },
                                "tools": [
                                    {
                                        "vendor": "OWASP",
                                        "name": "Dependency-Track",
                                        "version": "${json-unit.any-string}"
                                    }
                                ]
                            },
                            "components": [
                                {
                                    "type": "library",
                                    "bom-ref": "${json-unit.matches:componentWithoutVulnUuid}",
                                    "supplier": {
                                      "name": "componentSupplier"
                                    },
                                    "name": "acme-lib-a",
                                    "version": "1.0.0",
                                    "evidence": {
                                      "occurrences": [
                                        {
                                          "location": "/foo/bar"
                                        }
                                      ]
                                    },
                                    "properties": [
                                      {
                                        "name": "foo:bar",
                                        "value": "baz"
                                      }
                                    ]
                                },
                                {
                                    "type": "library",
                                    "bom-ref": "${json-unit.matches:componentWithVulnUuid}",
                                    "name": "acme-lib-b",
                                    "version": "1.0.0"
                                },
                                {
                                    "type": "library",
                                    "bom-ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                                    "name": "acme-lib-c",
                                    "version": "1.0.0"
                                }
                            ],
                            "dependencies": [
                                {
                                    "ref": "${json-unit.matches:projectUuid}",
                                    "dependsOn": [
                                        "${json-unit.matches:componentWithoutVulnUuid}",
                                        "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                                    ]
                                },
                                {
                                    "ref": "${json-unit.matches:componentWithoutVulnUuid}",
                                    "dependsOn": [
                                        "${json-unit.matches:componentWithVulnUuid}"
                                    ]
                                },
                                {
                                    "ref": "${json-unit.matches:componentWithVulnUuid}",
                                    "dependsOn": []
                                },
                                {
                                    "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                                    "dependsOn": []
                                }
                            ]
                        }
                        """));

        // Ensure the dependency graph did not get deleted during export.
        // https://github.com/DependencyTrack/dependency-track/issues/2494
        qm.getPersistenceManager().refreshAll(project, componentWithoutVuln, componentWithVuln, componentWithVulnAndAnalysis);
        assertThat(project.getDirectDependencies()).isNotNull();
        assertThat(componentWithoutVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVulnAndAnalysis.getDirectDependencies()).isNotNull();
    }

    @Test
    public void exportProjectAsCycloneDxLicenseTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        org.dependencytrack.model.License license = new org.dependencytrack.model.License();
        license.setId(1234);
        license.setName("CustomName");
        license.setCustomLicense(true);
        c.setResolvedLicense(license);
        c.setDirectDependencies("[]");
        Component component = qm.createComponent(c, false);
        qm.persist(project);
        Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withMatcher("component", equalTo(component.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ],
                        "component": {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "name": "Acme Example",
                            "version": "1.0"
                        }
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:component}",
                            "name": "sample-component",
                            "version": "1.0",
                            "licenses": [
                                {
                                    "license": {
                                        "name": "CustomName"
                                    }
                                }
                            ]
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:component}",
                            "dependsOn": []
                        }
                    ]
                }
                """));
    }

    @Test
    public void exportProjectAsCycloneDxInventoryWithVulnerabilitiesTest() {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);

        var project = new Project();
        project.setName("acme-app");
        project.setClassifier(Classifier.APPLICATION);
        project = qm.createProject(project, null, false);

        var componentWithoutVuln = new Component();
        componentWithoutVuln.setProject(project);
        componentWithoutVuln.setName("acme-lib-a");
        componentWithoutVuln.setVersion("1.0.0");
        componentWithoutVuln.setDirectDependencies("[]");
        componentWithoutVuln = qm.createComponent(componentWithoutVuln, false);

        var componentWithVuln = new Component();
        componentWithVuln.setProject(project);
        componentWithVuln.setName("acme-lib-b");
        componentWithVuln.setVersion("1.0.0");
        componentWithVuln.setDirectDependencies("[]");
        componentWithVuln = qm.createComponent(componentWithVuln, false);
        qm.addVulnerability(vulnerability, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnerability, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnerability, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

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

        final Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "withVulnerabilities")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("vulnUuid", equalTo(vulnerability.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentWithoutVulnUuid", equalTo(componentWithoutVuln.getUuid().toString()))
                .withMatcher("componentWithVulnUuid", equalTo(componentWithVuln.getUuid().toString()))
                .withMatcher("componentWithVulnAndAnalysisUuid", equalTo(componentWithVulnAndAnalysis.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "component": {
                            "type": "application",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "name": "acme-app",
                            "version": "SNAPSHOT"
                        },
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ]
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithoutVulnUuid}",
                            "name": "acme-lib-a",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnUuid}",
                            "name": "acme-lib-b",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "name": "acme-lib-c",
                            "version": "1.0.0"
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithoutVulnUuid}",
                                "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithoutVulnUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithVulnUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "dependsOn": []
                        }
                    ],
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
                            "affects": [
                                {
                                    "ref": "${json-unit.matches:componentWithVulnUuid}"
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
                            "affects": [
                                {
                                    "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                                }
                            ]
                        }
                    ]
                }
                """));

        // Ensure the dependency graph did not get deleted during export.
        // https://github.com/DependencyTrack/dependency-track/issues/2494
        qm.getPersistenceManager().refreshAll(project, componentWithoutVuln, componentWithVuln, componentWithVulnAndAnalysis);
        assertThat(project.getDirectDependencies()).isNotNull();
        assertThat(componentWithoutVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVulnAndAnalysis.getDirectDependencies()).isNotNull();
    }

    @Test
    public void exportProjectAsCycloneDxVdrTest() {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);

        var project = new Project();
        project.setName("acme-app");
        project.setClassifier(Classifier.APPLICATION);
        project = qm.createProject(project, null, false);

        var componentWithoutVuln = new Component();
        componentWithoutVuln.setProject(project);
        componentWithoutVuln.setName("acme-lib-a");
        componentWithoutVuln.setVersion("1.0.0");
        componentWithoutVuln.setDirectDependencies("[]");
        componentWithoutVuln = qm.createComponent(componentWithoutVuln, false);

        var componentWithVuln = new Component();
        componentWithVuln.setProject(project);
        componentWithVuln.setName("acme-lib-b");
        componentWithVuln.setVersion("1.0.0");
        componentWithVuln.setDirectDependencies("[]");
        componentWithVuln = qm.createComponent(componentWithVuln, false);
        qm.addVulnerability(vulnerability, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnerability, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnerability, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

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

        final Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "vdr")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .withMatcher("vulnUuid", equalTo(vulnerability.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentWithoutVulnUuid", equalTo(componentWithoutVuln.getUuid().toString()))
                .withMatcher("componentWithVulnUuid", equalTo(componentWithVuln.getUuid().toString()))
                .withMatcher("componentWithVulnAndAnalysisUuid", equalTo(componentWithVulnAndAnalysis.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "component": {
                            "type": "application",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "name": "acme-app",
                            "version": "SNAPSHOT"
                        },
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ]
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnUuid}",
                            "name": "acme-lib-b",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "name": "acme-lib-c",
                            "version": "1.0.0"
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "dependsOn": []
                        }
                    ],
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
                            "affects": [
                                {
                                    "ref": "${json-unit.matches:componentWithVulnUuid}"
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
                            "affects": [
                                {
                                    "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                                }
                            ],
                            "analysis": {
                                "state": "resolved",
                                "response": [
                                    "update"
                                ]
                            }
                        }
                    ]
                }
                """));

        // Ensure the dependency graph did not get deleted during export.
        // https://github.com/DependencyTrack/dependency-track/issues/2494
        qm.getPersistenceManager().refreshAll(project, componentWithoutVuln, componentWithVuln, componentWithVulnAndAnalysis);
        assertThat(project.getDirectDependencies()).isNotNull();
        assertThat(componentWithoutVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVulnAndAnalysis.getDirectDependencies()).isNotNull();
    }

    @Test
    public void exportComponentAsCycloneDx() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, null, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        Component component = qm.createComponent(c, false);
        Response response = jersey.target(V1_BOM + "/cyclonedx/component/" + component.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertTrue(body.startsWith("{"));
    }

    @Test
    public void exportComponentAsCycloneDxInvalid() {
        Response response = jersey.target(V1_BOM + "/cyclonedx/component/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void exportComponentAsCycloneDxAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_BOM + "/cyclonedx/component/" + component.getUuid())
                .queryParam("variant", "inventory")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    }

    @Test
    public void uploadBomTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        UUID uuid = UUID.fromString(json.getString("token"));
        assertThat(qm.getAllWorkflowStatesForAToken(uuid)).satisfiesExactlyInAnyOrder(
               workflowState -> {
                   assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.BOM_CONSUMPTION);
                   assertThat(workflowState.getToken()).isEqualTo(uuid);
                   assertThat(workflowState.getParent()).isNull();
                   assertThat(workflowState.getStartedAt()).isNull();
                   assertThat(workflowState.getUpdatedAt()).isNotNull();
               },
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.BOM_PROCESSING);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNotNull();
                    assertThat(workflowState.getStartedAt()).isNull();
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                },
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.VULN_ANALYSIS);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNotNull();
                    assertThat(workflowState.getStartedAt()).isNull();
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                },
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.POLICY_EVALUATION);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNotNull();
                    assertThat(workflowState.getStartedAt()).isNull();
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                },
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.METRICS_UPDATE);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNotNull();
                    assertThat(workflowState.getStartedAt()).isNull();
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                }
        );
    }

    @Test
    public void uploadNonCycloneDxBomTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        String bomString = Base64.getEncoder().encodeToString("""
                SPDXVersion: SPDX-2.2
                DataLicense: CC0-1.0
                """.getBytes());
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status":400,
                  "title": "The uploaded BOM is invalid",
                  "detail": "BOM is neither valid JSON nor XML"
                }
                """);
    }

    @Test
    public void uploadInvalidCycloneDxBomTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        String bomString = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "components": [
                    {
                      "version": "1.2.3"
                    }
                  ]
                }
                """.getBytes());
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "status": 400,
                          "title": "The uploaded BOM is invalid",
                          "detail": "Schema validation failed",
                          "errors": [
                            "$: required property 'version' not found",
                            "$.components[0]: required property 'type' not found",
                            "$.components[0]: required property 'name' not found"
                          ]
                        }
                        """);
    }

    @Test
    public void uploadInvalidFormatBomTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        File file = new File(IOUtils.resourceToURL("/unit/bom-invalid.json").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The uploaded BOM is invalid",
                  "detail": "BOM is neither valid JSON nor XML"
                }
                """);
    }

    @Test
    public void uploadBomInvalidProjectTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(UUID.randomUUID().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void uploadBomAutoCreateTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project project = qm.getProject("Acme Example", "1.0");
        Assert.assertNotNull(project);
    }

    @Test
    public void uploadBomUnauthorizedTest() throws Exception {
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(401, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The principal does not have permission to create project.", body);
    }

    @Test
    public void uploadBomAutoCreateTestWithParentTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        // Upload parent project
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Parent", "1.0", null, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Project parent = qm.getProject("Acme Parent", "1.0");
        Assert.assertNotNull(parent);
        String parentUUID = parent.getUuid().toString();

        // Upload first child, search parent by UUID
        request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, parentUUID, null, null, false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project child = qm.getProject("Acme Example", "1.0");
        Assert.assertNotNull(child);
        Assert.assertNotNull(child.getParent());
        Assert.assertEquals(parentUUID, child.getParent().getUuid().toString());


        // Upload second child, search parent by name+ver
        request = new BomSubmitRequest(null, "Acme Example", "2.0", null, true, null, "Acme Parent", "1.0", false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        child = qm.getProject("Acme Example", "2.0");
        Assert.assertNotNull(child);
        Assert.assertNotNull(child.getParent());
        Assert.assertEquals(parentUUID, child.getParent().getUuid().toString());

        // Upload third child, specify parent's UUID, name, ver. Name and ver are ignored when UUID is specified.
        request = new BomSubmitRequest(null, "Acme Example", "3.0", null, true, parentUUID, "Non-existent parent", "1.0", false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        child = qm.getProject("Acme Example", "3.0");
        Assert.assertNotNull(child);
        Assert.assertNotNull(child.getParent());
        Assert.assertEquals(parentUUID, child.getParent().getUuid().toString());
    }

    @Test
    public void uploadBomInvalidParentTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, UUID.randomUUID().toString(), null, null, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The parent project could not be found.", body);

        request = new BomSubmitRequest(null, "Acme Example", "2.0", null, true, null, "Non-existent parent", null, false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        body = getPlainTextBody(response);
        Assert.assertEquals("The parent project could not be found.", body);
    }

    @SuppressWarnings("unused")
    private Object[] uploadBomSchemaValidationTestParameters() throws Exception {
        final PathMatcher pathMatcherJson = FileSystems.getDefault().getPathMatcher("glob:**/valid-bom-*.json");
        final PathMatcher pathMatcherXml = FileSystems.getDefault().getPathMatcher("glob:**/valid-bom-*.xml");
        final var bomFilePaths = new ArrayList<Path>();

        Files.walkFileTree(Paths.get("./src/test/resources"), new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs) throws IOException {
                if (pathMatcherJson.matches(file) || pathMatcherXml.matches(file)) {
                    bomFilePaths.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });

        return bomFilePaths.stream().sorted().toArray();
    }

    @Test
    @Parameters(method = "uploadBomSchemaValidationTestParameters")
    public void uploadBomSchemaValidationTest(final Path filePath) throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        File file = filePath.toFile();
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadBomInvalidJsonTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

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

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));

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

        assertThat(kafkaMockProducer.history()).hasSize(1);
        final org.dependencytrack.proto.notification.v1.Notification validationFailureNotification =
                deserializeValue(KafkaTopics.NOTIFICATION_BOM, kafkaMockProducer.history().getFirst());
        assertThat(validationFailureNotification).isNotNull();
        assertThat(validationFailureNotification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(validationFailureNotification.getGroup()).isEqualTo(GROUP_BOM_VALIDATION_FAILED);
        assertThat(validationFailureNotification.getLevel()).isEqualTo(LEVEL_ERROR);
        assertThat(validationFailureNotification.getTitle()).isEqualTo(NotificationConstants.Title.BOM_VALIDATION_FAILED);
        assertThat(validationFailureNotification.getContent()).isEqualTo("An error occurred while validating a BOM");
        assertThat(validationFailureNotification.getSubject().is(BomValidationFailedSubject.class)).isTrue();

        final var subject = validationFailureNotification.getSubject().unpack(BomValidationFailedSubject.class);
        assertThat(subject.getBom().getFormat()).isEmpty();
        assertThat(subject.getBom().getSpecVersion()).isEmpty();
        assertThat(subject.getBom().getContent()).isEqualTo("(Omitted)");
        assertThat(subject.getErrorsList()).containsOnly("""
                $.components[0].type: does not have a value in the enumeration \
                ["application", "framework", "library", "container", "operating-system", \
                "device", "firmware", "file"]""");
    }

    @Test
    public void uploadBomInvalidXmlTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedBom = Base64.getEncoder().encodeToString("""
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

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));

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

        assertThat(kafkaMockProducer.history()).hasSize(1);
        final org.dependencytrack.proto.notification.v1.Notification validationFailureNotification =
                deserializeValue(KafkaTopics.NOTIFICATION_BOM, kafkaMockProducer.history().getFirst());
        assertThat(validationFailureNotification).isNotNull();
        assertThat(validationFailureNotification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
        assertThat(validationFailureNotification.getGroup()).isEqualTo(GROUP_BOM_VALIDATION_FAILED);
        assertThat(validationFailureNotification.getLevel()).isEqualTo(LEVEL_ERROR);
        assertThat(validationFailureNotification.getTitle()).isEqualTo(NotificationConstants.Title.BOM_VALIDATION_FAILED);
        assertThat(validationFailureNotification.getContent()).isEqualTo("An error occurred while validating a BOM");
        assertThat(validationFailureNotification.getSubject().is(BomValidationFailedSubject.class)).isTrue();

        final var subject = validationFailureNotification.getSubject().unpack(BomValidationFailedSubject.class);
        assertThat(subject.getBom().getFormat()).isEmpty();
        assertThat(subject.getBom().getSpecVersion()).isEmpty();
        assertThat(subject.getBom().getContent()).isEqualTo("(Omitted)");
        assertThat(subject.getErrorsList()).containsExactlyInAnyOrder(
                "cvc-enumeration-valid: Value 'foo' is not facet-valid with respect to enumeration '[application, framework, library, container, operating-system, device, firmware, file]'. It must be a value from the enumeration.",
                "cvc-attribute.3: The value 'foo' of attribute 'type' on element 'component' is not valid with respect to its type, 'classification'.");
    }

    @Test
    public void uploadBomTooLargeViaPutTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String bom = "a".repeat(StreamReadConstraints.DEFAULT_MAX_STRING_LEN + 1);

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(bom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The provided JSON payload could not be mapped",
                  "detail": "The BOM is too large to be transmitted safely via Base64 encoded JSON value. Please use the \\"POST /api/v1/bom\\" endpoint with Content-Type \\"multipart/form-data\\" instead. Original cause: String value length (20000001) exceeds the maximum allowed (20000000, from `StreamReadConstraints.getMaxStringLength()`) (through reference chain: org.dependencytrack.resources.v1.vo.BomSubmitRequest[\\"bom\\"])"
                }
                """);
    }

    @Test
    public void uploadBomAutoCreateWithTagsMultipartTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        final var multiPart = new FormDataMultiPart()
                .field("bom", resourceToString("/unit/bom-1.xml", StandardCharsets.UTF_8), MediaType.APPLICATION_XML_TYPE)
                .field("projectName", "Acme Example")
                .field("projectVersion", "1.0")
                .field("projectTags", "tag1,tag2")
                .field("autoCreate", "true");

        // NB: The GrizzlyConnectorProvider doesn't work with MultiPart requests.
        // https://github.com/eclipse-ee4j/jersey/issues/5094
        final var client = ClientBuilder.newClient(new ClientConfig()
                .register(MultiPartFeature.class)
                .connectorProvider(new HttpUrlConnectorProvider()));

        final Response response = client.target(jersey.target(V1_BOM).getUri()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(multiPart, multiPart.getMediaType()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "token": "${json-unit.any-string}"
                }
                """);

        final Project project = qm.getProject("Acme Example", "1.0");
        assertThat(project).isNotNull();
        assertThat(project.getTags())
                .extracting(Tag::getName)
                .containsExactlyInAnyOrder("tag1", "tag2");
    }

    @Test
    public void uploadBomProtobufFormatTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        final var project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomProto = Bom.newBuilder().setSpecVersion("1.6").build();
        final var multiPart = new FormDataMultiPart()
                .field("project", project.getUuid().toString())
                .field("bom", bomProto.toByteArray(), new MediaType("application", "x.vnd.cyclonedx+protobuf"))
                .field("autoCreate", "true");

        // NB: The GrizzlyConnectorProvider doesn't work with MultiPart requests.
        // https://github.com/eclipse-ee4j/jersey/issues/5094
        final var client = ClientBuilder.newClient(new ClientConfig()
                .register(MultiPartFeature.class)
                .connectorProvider(new HttpUrlConnectorProvider()));

        final Response response = client.target(jersey.target(V1_BOM).getUri()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(multiPart, multiPart.getMediaType()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "token": "${json-unit.any-string}"
                }
                """);

        final var projectResponse = qm.getProject("Acme Example", "1.0");
        assertThat(projectResponse).isNotNull();
        assertThat(projectResponse.getName()).isEqualTo(project.getName());
    }

    @Test
    public void uploadBomAutoCreateWithTagsTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        File file = new File(IOUtils.resourceToURL("/unit/bom-1.xml").toURI());
        String bomString = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
        List<Tag> tags = Stream.of("tag1", "tag2").map(name -> {
            Tag tag = new Tag();
            tag.setName(name);
            return tag;
        }).collect(Collectors.toList());
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", tags, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project project = qm.getProject("Acme Example", "1.0");
        Assert.assertNotNull(project);
        assertThat(project.getTags())
                .extracting(Tag::getName)
                .containsExactlyInAnyOrder("tag1", "tag2");
    }

    @Test
    public void validateCycloneDxBomWithMultipleNamespacesTest() throws Exception {
        byte[] bom = resourceToByteArray("/unit/bom-issue4008.xml");
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(bom));
    }

    @Test
    public void uploadBomWithValidationModeDisabledTest() {
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

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadBomWithValidationModeEnabledForTagsTest() {
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

        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);

        qm.bind(project, Collections.emptyList());

        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadBomWithValidationModeDisabledForTagsTest() {
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

        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.bind(project, Collections.emptyList());

        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void uploadBomWithValidationTagsInvalidTest() {
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
                "invalid",
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

        // With validation mode ENABLED_FOR_TAGS, and invalid tags,
        // should fall back to NOT validating.
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.bind(project, Collections.emptyList());

        // Removal of the project tag should not make a difference.
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void uploadBomAutoCreateLatestWithAclTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        enablePortfolioAccessControl();

        final var accessLatestProject = new Project();
        accessLatestProject.setName("acme-app-a");
        accessLatestProject.setVersion("1.0.0");
        accessLatestProject.setIsLatest(true);
        accessLatestProject.setAccessTeams(Set.of(team));
        qm.persist(accessLatestProject);

        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, accessLatestProject.getName(),
                "1.0.1", null, true, true, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertNotNull(json.getString("token"));
    }

    @Test
    public void uploadBomAutoCreateLatestWithAclNoAccessTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        enablePortfolioAccessControl();

        final var noAccessLatestProject = new Project();
        noAccessLatestProject.setName("acme-app-a");
        noAccessLatestProject.setVersion("1.0.0");
        noAccessLatestProject.setIsLatest(true);
        qm.persist(noAccessLatestProject);

        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, noAccessLatestProject.getName(),
                "1.0.1", null, true, true, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(403, response.getStatus(), 0);
    }
}
