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
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.WorkflowStep;
import org.dependencytrack.persistence.CweImporter;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.WorkflowStatus.PENDING;
import static org.junit.Assert.assertEquals;

public class FindingResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(FindingResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)))
                .build();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        new CweImporter().processCweDefinitions();
    }

    @Test
    public void getFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        assertThat(json).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                }
        );
    }

    @Test
    public void getFindingsByProjectInvalidTest() {
        Response response = target(V1_FINDING + "/project/" + UUID.randomUUID().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        assertEquals("The project could not be found.", body);
    }

    @Test
    public void exportFindingsByProjectTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals(Config.getInstance().getApplicationName(), json.getJsonObject("meta").getString("application"));
        assertEquals(Config.getInstance().getApplicationVersion(), json.getJsonObject("meta").getString("version"));
        Assert.assertNotNull(json.getJsonObject("meta").getString("timestamp"));
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
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                }
        );
    }

    @Test
    public void exportFindingsByProjectInvalidTest() {
        Response response = target(V1_FINDING + "/project/" + UUID.randomUUID().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        assertEquals("The project could not be found.", body);
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionTest() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, true, false);
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

        Component c3 = createComponent(p1, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");

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

        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v2, c1, AnalyzerIdentity.NONE);
        qm.addVulnerability(v3, c2, AnalyzerIdentity.NONE);
        qm.addVulnerability(v4, c5, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        assertThat(json).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("2.0.0", finding.getJsonObject("component").getString("latestVersion"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("2.0.0", finding.getJsonObject("component").getString("latestVersion"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(80, finding.getJsonObject("vulnerability").getInt("cweId"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("3.0.0", finding.getJsonObject("component").getString("latestVersion"));
                }
        );
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionWithoutRepositoryMetaComponent() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);
        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getInt("cweId"));
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        Assert.assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        Assert.assertThrows(NullPointerException.class, () -> json.getJsonObject(0).getJsonObject("component").getString("latestVersion"));
    }

    @Test
    public void testWorkflowStepsShouldBeCreatedOnReanalyze() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        Response response = target(V1_FINDING + "/project/" + p1.getUuid().toString() +  "/analyze").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("{}"));
        Map<String, String> responseMap = response.readEntity(Map.class);

        Assert.assertEquals(200, response.getStatus(), 0);

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
}
