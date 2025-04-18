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

import alpine.Config;
import alpine.model.About;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.WorkflowStep;
import org.glassfish.jersey.server.ResourceConfig;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.dependencytrack.resources.v1.FindingResource.MEDIA_TYPE_SARIF_JSON;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class FindingResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(FindingResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    public void getFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        createComponent(p1, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertThat(json).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                }
        );
    }

    @Test
    public void getFindingsByProjectEmptyTest() {
        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("com.acme");
        metaComponent.setName("acme-lib");
        metaComponent.setLatestVersion("1.2.3");
        metaComponent.setLastCheck(new Date());
        qm.persist(metaComponent);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_FINDING + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getFindingsByProjectInvalidTest() {
        Response response = jersey.target(V1_FINDING + "/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(404, response.getStatus(), 0);
        assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        assertEquals("The project could not be found.", body);
    }

    @Test
    public void getFindingsByProjectAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_FINDING + "/project/" + project.getUuid()).request()
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
    public void exportFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        createComponent(p1, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        assertNotNull(json);
        assertEquals(Config.getInstance().getApplicationName(), json.getJsonObject("meta").getString("application"));
        assertEquals(Config.getInstance().getApplicationVersion(), json.getJsonObject("meta").getString("version"));
        assertNotNull(json.getJsonObject("meta").getString("timestamp"));
        assertEquals("Acme Example", json.getJsonObject("project").getString("name"));
        assertEquals("1.0", json.getJsonObject("project").getString("version"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject("project").getString("uuid"));
        assertEquals("1.2", json.getString("version")); // FPF version
        JsonArray findings = json.getJsonArray("findings");
        assertThat(findings).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                }
        );
    }

    @Test
    public void exportFindingsByProjectInvalidTest() {
        Response response = jersey.target(V1_FINDING + "/project/" + UUID.randomUUID() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(404, response.getStatus(), 0);
        assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        assertEquals("The project could not be found.", body);
    }

    @Test
    public void exportFindingsByProjectAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_FINDING + "/project/" + project.getUuid() + "/export").request()
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
    public void getFindingsByProjectWithComponentLatestVersionTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");
        RepositoryMetaComponent r1 = new RepositoryMetaComponent();
        Date d1 = new Date();
        r1.setLastCheck(d1);
        r1.setNamespace("org.acme");
        r1.setName("component-a");
        r1.setLatestVersion("2.0.0");
        r1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r1);

        Component c2 = createComponent(p1, "Component B", "1.0");
        c2.setPurl("pkg:/maven/org.acme/component-b@1.0.0");
        RepositoryMetaComponent r2 = new RepositoryMetaComponent();
        Date d2 = new Date();
        r2.setLastCheck(d2);
        r2.setNamespace("org.acme");
        r2.setName("component-b");
        r2.setLatestVersion("3.0.0");
        r2.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r2);

        createComponent(p1, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");

        Component c5 = createComponent(p2, "Component E", "1.0");
        c5.setPurl("pkg:/maven/org.acme/component-e@1.0.0");
        RepositoryMetaComponent r3 = new RepositoryMetaComponent();
        Date d3 = new Date();
        r3.setLastCheck(d3);
        r3.setNamespace("org.acme");
        r3.setName("component-e");
        r3.setLatestVersion("4.0.0");
        r3.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(r3);

        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertThat(json).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("2.0.0", finding.getJsonObject("component").getString("latestVersion"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("2.0.0", finding.getJsonObject("component").getString("latestVersion"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("3.0.0", finding.getJsonObject("component").getString("latestVersion"));
                }
        );
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionWithoutRepositoryMetaComponent() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        assertNull(json.getJsonObject(0).getJsonObject("component").get("latestVersion"));
    }

    @Test
    public void getFindingsByProjectWithCvssAndOwaspData() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        v1.setCvssV2BaseScore(BigDecimal.valueOf(0.2));
        v1.setCvssV3BaseScore(BigDecimal.valueOf(0.3));
        v1.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(0.4));
        v1.setCvssV2Vector("cvssV2-vector");
        v1.setCvssV3Vector("cvssV3-vector");
        v1.setOwaspRRVector("owasp-vector");
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);

        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals(0.2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("cvssV2BaseScore").doubleValue(), 0);
        assertEquals(0.3, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("cvssV3BaseScore").doubleValue(), 0);
        assertEquals(0.4, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("owaspBusinessImpactScore").doubleValue(), 0);
        assertEquals("cvssV2-vector", json.getJsonObject(0).getJsonObject("vulnerability").getString("cvssV2Vector"));
        assertEquals("cvssV3-vector", json.getJsonObject(0).getJsonObject("vulnerability").getString("cvssV3Vector"));
        assertEquals("owasp-vector", json.getJsonObject(0).getJsonObject("vulnerability").getString("owaspRRVector"));
    }

    @Test
    public void testWorkflowStepsShouldBeCreatedOnReanalyze() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString() +  "/analyze").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("{}"));
        Map<String, String> responseMap = response.readEntity(Map.class);

        assertEquals(200, response.getStatus(), 0);

        UUID uuid = UUID.fromString(responseMap.get("token"));
        assertThat(qm.getAllWorkflowStatesForAToken(uuid)).satisfiesExactlyInAnyOrder(
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.VULN_ANALYSIS);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNull();
                    assertThat(workflowState.getStatus()).isEqualTo(PENDING);
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                    assertThat(workflowState.getStartedAt()).isNull();
                },
                workflowState -> {
                    assertThat(workflowState.getStep()).isEqualTo(WorkflowStep.POLICY_EVALUATION);
                    assertThat(workflowState.getToken()).isEqualTo(uuid);
                    assertThat(workflowState.getParent()).isNotNull();
                    assertThat(workflowState.getStatus()).isEqualTo(PENDING);
                    assertThat(workflowState.getUpdatedAt()).isNotNull();
                    assertThat(workflowState.getStartedAt()).isNull();
                }
        );
    }

    @Test
    public void getAllFindings() {
        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example 2", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example 3", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING)
                .queryParam("sortName", "component.projectName")
                .queryParam("sortOrder", "asc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(5, json.size());
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1_child.getName() ,json.getJsonObject(3).getJsonObject("component").getString("projectName"));
        assertEquals(p1_child.getVersion() ,json.getJsonObject(3).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1_child.getUuid().toString(), json.getJsonObject(3).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(4).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p2.getName() ,json.getJsonObject(4).getJsonObject("component").getString("projectName"));
        assertEquals(p2.getVersion() ,json.getJsonObject(4).getJsonObject("component").getString("projectVersion"));
        assertEquals(p2.getUuid().toString(), json.getJsonObject(4).getJsonObject("component").getString("project"));
    }

    @Test
    public void getAllFindingsSortedBySeverity() {
        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.MEDIUM);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.HIGH);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c1, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING)
                .queryParam("sortName", "vulnerability.severity")
                .queryParam("sortOrder", "desc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(3, json.size());
        assertEquals(v1.getSeverity().name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals(v3.getSeverity().name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        assertEquals(v2.getSeverity().name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
    }

    @Test
    public void getAllFindingsWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example Child", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Team team = qm.createTeam("Team Acme");
        ApiKey apiKey = qm.createApiKey(team);
        p1.addAccessTeam(team);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }
        Response response = jersey.target(V1_FINDING).request()
                .header(X_API_KEY, apiKey.getKey())
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(4, json.size());
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(3).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(3).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(3).getJsonObject("component").getString("project"));

        // Findings of p1_child are returned because team was given access to its parent project p1.
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1_child.getName(), json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        assertEquals(p1_child.getVersion(), json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1_child.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
    }

    @Test
    public void getAllFindingsGroupedByVulnerability() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example Child", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c4, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c6, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = jersey.target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(4, json.size());
        assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(3, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(3).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-4", json.getJsonObject(3).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.LOW.name(), json.getJsonObject(3).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(3).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(3).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    public void getAllFindingsGroupedByVulnerabilityWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example Child", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Team team = qm.createTeam("Team Acme");
        ApiKey apiKey = qm.createApiKey(team);
        p1.addAccessTeam(team);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c3, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c4, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c6, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }
        Response response = jersey.target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey.getKey())
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(3, json.size());
        assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount")); // p1 and p1_child.

        assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        assertEquals("NONE", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    public void getSARIFFindingsByProjectTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(project, "Component 1", "1.1.4");
        Component c2 = createComponent(project, "Component 2", "2.78.123");
        c1.setGroup("org.acme");
        c2.setGroup("com.xyz");
        c1.setPurl("pkg:maven/org.acme/component1@1.1.4?type=jar");
        c2.setPurl("pkg:maven/com.xyz/component2@2.78.123?type=jar");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL, "Vuln Title 1", "This is a description", null, 80);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH, "Vuln Title 2", "   Yet another description but with surrounding whitespaces   ", "", 46);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.LOW, "Vuln Title 3", "A description-with-hyphens-(and parentheses)", "  Recommendation with whitespaces  ", 23);

        // Note: Same vulnerability added to multiple components to test whether "rules" field doesn't contain duplicates
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);

        Response response = jersey.target(V1_FINDING + "/project/" + project.getUuid().toString()).request()
                .header(HttpHeaders.ACCEPT, MEDIA_TYPE_SARIF_JSON)
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertEquals(200, response.getStatus(), 0);
        assertEquals(MEDIA_TYPE_SARIF_JSON, response.getHeaderString(HttpHeaders.CONTENT_TYPE));
        final String jsonResponse = getPlainTextBody(response);
        JSONArray resultArray = new JSONObject(jsonResponse).getJSONArray("runs").getJSONObject(0).getJSONArray("results");

        assertThatJson(jsonResponse)
                .withMatcher("version", equalTo(new About().getVersion()))
                .withMatcher("fullName", equalTo("OWASP Dependency-Track - " + new About().getVersion()));

        assertThat(resultArray).hasSize(4);
        assertThat(resultArray).satisfiesExactlyInAnyOrder(
                vuln1 -> assertThatJson(vuln1).isEqualTo("""
                        {
                          "ruleId": "Vuln-1",
                          "message": {
                            "text": "This is a description"
                          },
                          "locations": [
                            {
                              "logicalLocations": [
                                {
                                  "fullyQualifiedName": "pkg:maven/org.acme/component1@1.1.4?type=jar"
                                }
                              ]
                            }
                          ],
                          "level": "error",
                          "properties": {
                            "name": "Component 1",
                            "group": "org.acme",
                            "version": "1.1.4",
                            "source": "INTERNAL",
                            "cwes": [
                                {
                                    "cweId": "80",
                                    "name": "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)"
                                }
                            ],
                            "cvssV3BaseScore": "",
                            "epssScore": "",
                            "epssPercentile": "",
                            "severityRank": "0",
                            "recommendation": ""
                          }
                        }
                """),
                vuln2 -> assertThatJson(vuln2).isEqualTo("""
                        {
                           "ruleId": "Vuln-2",
                           "message": {
                             "text": "Yet another description but with surrounding whitespaces"
                           },
                           "locations": [
                             {
                               "logicalLocations": [
                                 {
                                   "fullyQualifiedName": "pkg:maven/org.acme/component1@1.1.4?type=jar"
                                 }
                               ]
                             }
                           ],
                           "level": "error",
                           "properties": {
                             "name": "Component 1",
                             "group": "org.acme",
                             "version": "1.1.4",
                             "source": "INTERNAL",
                             "cwes": [
                                {
                                    "cweId": "46",
                                    "name": "Path Equivalence: 'filename ' (Trailing Space)"
                                }
                             ],
                             "cvssV3BaseScore": "",
                             "epssScore": "",
                             "epssPercentile": "",
                             "severityRank": "1",
                             "recommendation": ""
                           }
                        }
                """),
                vuln3 -> assertThatJson(vuln3).isEqualTo("""
                        {
                           "ruleId": "Vuln-3",
                           "message": {
                             "text": "A description-with-hyphens-(and parentheses)"
                           },
                           "locations": [
                             {
                               "logicalLocations": [
                                 {
                                   "fullyQualifiedName": "pkg:maven/org.acme/component1@1.1.4?type=jar"
                                 }
                               ]
                             }
                           ],
                           "level": "note",
                           "properties": {
                             "name": "Component 1",
                             "group": "org.acme",
                             "version": "1.1.4",
                             "source": "INTERNAL",
                             "cwes": [
                                {
                                    "cweId": "23",
                                    "name": "Relative Path Traversal"
                                }
                             ],
                             "cvssV3BaseScore": "",
                             "epssScore": "",
                             "epssPercentile": "",
                             "severityRank": "3",
                             "recommendation": "Recommendation with whitespaces"
                           }
                        }
                """),
                vuln3 -> assertThatJson(vuln3).isEqualTo("""
                        {
                           "ruleId": "Vuln-3",
                           "message": {
                             "text": "A description-with-hyphens-(and parentheses)"
                           },
                           "locations": [
                             {
                               "logicalLocations": [
                                 {
                                   "fullyQualifiedName": "pkg:maven/com.xyz/component2@2.78.123?type=jar"
                                 }
                               ]
                             }
                           ],
                           "level": "note",
                           "properties": {
                             "name": "Component 2",
                             "group": "com.xyz",
                             "version": "2.78.123",
                             "source": "INTERNAL",
                             "cwes": [
                                {
                                    "cweId": "23",
                                    "name": "Relative Path Traversal"
                                }
                             ],
                             "cvssV3BaseScore": "",
                             "epssScore": "",
                             "epssPercentile": "",
                             "severityRank": "3",
                             "recommendation": "Recommendation with whitespaces"
                           }
                        }
                """)
        );
    }

    @Test
    public void getFindingsByProjectWithPaginationTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 5; i++) {
            Component component = createComponent(p1, "Component "+i, "1.0."+i);
            Vulnerability vulnerability = createVulnerability("Vuln-"+i, Severity.LOW);
            qm.addVulnerability(vulnerability, component, AnalyzerIdentity.NONE);
        }

        Response response = jersey.target(V1_FINDING  + "/project/" + p1.getUuid())
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(3);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-0");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-1");
        assertThat(json.get(2).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-2");

        response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-3");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-4");

    }

    @Test
    public void getAllFindingsWithPaginationTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 5; i++) {
            Component component = createComponent(p1, "Component "+i, "1.0."+i);
            Vulnerability vulnerability = createVulnerability("Vuln-"+i, Severity.LOW);
            qm.addVulnerability(vulnerability, component, AnalyzerIdentity.NONE);
        }

        Response response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(3);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-0");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-1");
        assertThat(json.get(2).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-2");

        response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-3");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-4");

    }

    @Test
    public void getAllGroupedFindingsWithPaginationTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 5; i++) {
            Component component = createComponent(p1, "Component "+i, "1.0."+i);
            Vulnerability vulnerability = createVulnerability("Vuln-"+i, Severity.LOW);
            qm.addVulnerability(vulnerability, component, AnalyzerIdentity.NONE);
        }

        Response response = jersey.target(V1_FINDING + "/grouped")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(3);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-0");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-1");
        assertThat(json.get(2).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-2");

        response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-3");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-4");

    }

    private Component createComponent(Project project, String name, String version) {
        Component component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        return qm.createComponent(component, false);
    }

    private Vulnerability createVulnerability(String vulnId, Severity severity) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        return qm.createVulnerability(vulnerability, false);
    }

    private Vulnerability createVulnerability(String vulnId, Severity severity, String title, String description, String recommendation, Integer cweId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setTitle(title);
        vulnerability.setDescription(description);
        vulnerability.setRecommendation(recommendation);
        vulnerability.setCwes(List.of(cweId));
        return qm.createVulnerability(vulnerability, false);
    }
}
