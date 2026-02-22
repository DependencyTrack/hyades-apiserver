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
package org.dependencytrack.resources.v2;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Advisory;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.Set;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.resources.v2.OpenApiValidationClientResponseFilter.DISABLE_OPENAPI_VALIDATION;

/**
 * Tests for {@link AdvisoriesResource}.
 *
 * @author Christian Banse
 * @since 5.7.0
 */
public class AdvisoriesResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig());

    @Test
    public void testListAdvisories() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_READ);

        final Advisory advisory1 = new Advisory();
        advisory1.setTitle("Test Advisory 1");
        advisory1.setUrl("https://example.com/advisory1");
        advisory1.setContent("{\"test\":\"content1\"}");
        advisory1.setLastFetched(Instant.now());
        advisory1.setPublisher("publisher1");
        advisory1.setName("ADV-001");
        advisory1.setVersion("1.0");
        advisory1.setFormat("CSAF");
        advisory1.setSeenAt(Instant.now());
        qm.synchronizeAdvisory(advisory1);

        final Advisory advisory2 = new Advisory();
        advisory2.setTitle("Test Advisory 2");
        advisory2.setUrl("https://example.com/advisory2");
        advisory2.setContent("{\"test\":\"content2\"}");
        advisory2.setLastFetched(Instant.now());
        advisory2.setPublisher("publisher2");
        advisory2.setName("ADV-002");
        advisory2.setVersion("2.0");
        advisory2.setFormat("CSAF");
        qm.synchronizeAdvisory(advisory2);

        final Response response = jersey.target("/advisories")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "id": "${json-unit.any-string}",
                      "title": "Test Advisory 1",
                      "url": "https://example.com/advisory1",
                      "seen_at": "${json-unit.any-number}",
                      "last_fetched": "${json-unit.any-number}",
                      "publisher": "publisher1",
                      "name": "ADV-001",
                      "version": "1.0",
                      "affected_component_count": 0,
                      "affected_project_count": 0,
                      "format": "CSAF"
                    },
                    {
                      "id": "${json-unit.any-string}",
                      "title": "Test Advisory 2",
                      "url": "https://example.com/advisory2",
                      "last_fetched": "${json-unit.any-number}",
                      "publisher": "publisher2",
                      "name": "ADV-002",
                      "version": "2.0",
                      "affected_component_count": 0,
                      "affected_project_count": 0,
                      "format": "CSAF"
                    }
                  ],
                  "total": {
                    "count": 2,
                    "type": "EXACT"
                  }
                }
                """);
    }

    @Test
    public void testListAdvisoriesWithFormatFilter() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_READ);

        // Create advisories with different formats
        final Advisory csafAdvisory = new Advisory();
        csafAdvisory.setTitle("CSAF Advisory");
        csafAdvisory.setUrl("https://example.com/csaf");
        csafAdvisory.setContent("{\"test\":\"csaf\"}");
        csafAdvisory.setLastFetched(Instant.now());
        csafAdvisory.setPublisher("publisher1");
        csafAdvisory.setName("CSAF-001");
        csafAdvisory.setVersion("1.0");
        csafAdvisory.setFormat("CSAF");
        csafAdvisory.setSeenAt(Instant.now());
        qm.synchronizeAdvisory(csafAdvisory);

        final Advisory vexAdvisory = new Advisory();
        vexAdvisory.setTitle("VEX Advisory");
        vexAdvisory.setUrl("https://example.com/vex");
        vexAdvisory.setContent("{\"test\":\"vex\"}");
        vexAdvisory.setLastFetched(Instant.now());
        vexAdvisory.setPublisher("publisher2");
        vexAdvisory.setName("VEX-001");
        vexAdvisory.setVersion("1.0");
        vexAdvisory.setFormat("VEX");
        qm.synchronizeAdvisory(vexAdvisory);

        // Test filtering by CSAF format
        Response response = jersey.target("/advisories")
                .queryParam("format", "CSAF")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        JsonArray advisories = json.getJsonArray("items");
        assertThat(advisories).hasSize(1);
        assertThat(advisories.getJsonObject(0).getString("title"))
                .isEqualTo("CSAF Advisory");
        assertThat(advisories.getJsonObject(0).getString("format"))
                .isEqualTo("CSAF");
    }

    @Test
    public void testMarkAdvisoryAsSeen() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_UPDATE);

        // Create an unseen advisory
        Advisory advisory = new Advisory();
        advisory.setTitle("Unseen Advisory");
        advisory.setUrl("https://example.com/advisory");
        advisory.setContent("{\"test\":\"content\"}");
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher("publisher");
        advisory.setName("ADV-001");
        advisory.setVersion("1.0");
        advisory.setFormat("CSAF");
        advisory = qm.synchronizeAdvisory(advisory);

        Response response = jersey.target("/advisories/%s/mark-seen".formatted(advisory.getId()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();
    }

    @Test
    public void testGetAdvisoryById() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_READ);

        Advisory advisory = new Advisory();
        advisory.setTitle("Single Advisory");
        advisory.setUrl("https://example.com/single");
        advisory.setContent("{\"test\":\"single\"}");
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher("publisher");
        advisory.setName("ADV-SINGLE");
        advisory.setVersion("1.0");
        advisory.setFormat("CSAF");
        advisory.setSeenAt(Instant.now());
        advisory = qm.synchronizeAdvisory(advisory);

        Response response = jersey.target("/advisories/" + advisory.getId())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "${json-unit.any-string}",
                  "title": "Single Advisory",
                  "url": "https://example.com/single",
                  "seen_at": "${json-unit.any-number}",
                  "last_fetched": "${json-unit.any-number}",
                  "publisher": "publisher",
                  "name": "ADV-SINGLE",
                  "version": "1.0",
                  "affected_component_count": 0,
                  "affected_project_count": 0,
                  "format": "CSAF",
                  "content": "{\\"test\\":\\"single\\"}"
                }
                """);
    }

    @Test
    public void testGetAdvisoryNotFound() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_READ);

        final Response response = jersey.target("/advisories/b87d3c98-0bbe-42e5-892b-c56c5caa18f9")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void testDeleteAdvisory() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_DELETE);

        Advisory advisory = new Advisory();
        advisory.setTitle("Advisory to Delete");
        advisory.setUrl("https://example.com/advisory");
        advisory.setContent("{\"test\":\"content\"}");
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher("publisher");
        advisory.setName("ADV-DEL");
        advisory.setVersion("1.0");
        advisory.setFormat("CSAF");
        advisory = qm.synchronizeAdvisory(advisory);

        final Response response = jersey.target("/advisories/" + advisory.getId())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    public void testDeleteAdvisoryNotFound() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_DELETE);

        Response response = jersey.target("/advisories/d308eccc-9267-4caa-bf55-7f687dd4e5da")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void testUploadAdvisoryCsafInvalid_returns400() {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_CREATE);

        // Create a multipart form with an invalid CSAF payload and POST it
        try (FormDataMultiPart multiPart = new FormDataMultiPart().field("file", "this is not valid csaf json");
             Response response = jersey.target("/advisories")
                     .queryParam("format", "CSAF")
                     .request()
                     .property(DISABLE_OPENAPI_VALIDATION, "true")
                     .header(X_API_KEY, apiKey)
                     .post(Entity.entity(multiPart, multiPart.getMediaType()))) {
            // OpenAPI validation is disabled so we can assert the real response from the server
            assertThat(response.getStatus()).isEqualTo(400);
        } catch (IOException e) {
            assertThat(true).withFailMessage("IOException during test execution: " + e.getMessage()).isFalse();
        }
    }

    @Test
    public void testUploadAdvisoryCsafValid_returns200() throws Exception {
        initializeWithPermissions(Permissions.VULNERABILITY_MANAGEMENT_CREATE);

        // Load a valid CSAF document from test resources
        String csafContent = new String(
                getClass().getResourceAsStream("/csaf/oasis_csaf_tc-csaf_2_0-2021-6-1-04-11.json").readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8
        );

        // Create a multipart form with a valid CSAF payload and POST it
        try (FormDataMultiPart multiPart = new FormDataMultiPart().field("file", csafContent);
             final var client = ClientBuilder.newClient(new ClientConfig()
                     .register(MultiPartFeature.class)
                     .connectorProvider(new HttpUrlConnectorProvider()));

             var response = client.target(jersey.target("/advisories").getUri())
                     .queryParam("format", "CSAF")
                     .request()
                     .property(DISABLE_OPENAPI_VALIDATION, "true")
                     .header(X_API_KEY, apiKey)
                     .post(Entity.entity(multiPart, multiPart.getMediaType()))) {

            // If not 200, print the error for debugging
            if (response.getStatus() != 200) {
                String errorBody = response.readEntity(String.class);
                System.out.println("Error response: " + errorBody);
            }

            // Assert successful upload
            assertThat(response.getStatus()).isEqualTo(200);
        }
    }

    @Test
    public void listAdvisoriesForProjectShouldReturnAdvisoriesAffectingTheProject() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        final var advisory = new Advisory();
        advisory.setPublisher("ACME Inc.");
        advisory.setName("TEST-001");
        advisory.setVersion("1.0");
        advisory.setUrl("https://example.com/advisory");
        advisory.setTitle("Test Advisory");
        advisory.setFormat("CSAF");
        advisory.setLastFetched(Instant.now());
        advisory.setVulnerabilities(Set.of(vuln));
        qm.persist(advisory);

        final Response response = jersey.target("/projects/%s/advisories".formatted(project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "id": "${json-unit.any-string}",
                      "publisher": "ACME Inc.",
                      "name": "TEST-001",
                      "version": "1.0",
                      "title": "Test Advisory",
                      "url": "https://example.com/advisory",
                      "last_fetched": "${json-unit.any-number}",
                      "format": "CSAF",
                      "findings_count": 1
                    }
                  ],
                  "total": {
                    "count": 1,
                    "type": "EXACT"
                  }
                }
                """);
    }

}
