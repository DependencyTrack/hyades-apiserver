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
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.util.KafkaTestUtil;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import javax.jdo.JDOObjectNotFoundException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_FAILED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_UNKNOWN;
import static org.hamcrest.Matchers.equalTo;

public class ComponentResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ComponentResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    public void getComponentsDefaultRequestTest() {
        Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(405, response.getStatus()); // No longer prohibited in DT 4.0+
    }

    @Test
    public void getComponentByUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
    }

    @Test
    public void getComponentByInvalidUuidTest() {
        Response response = jersey.target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component could not be found.", body);
    }

    @Test
    public void getComponentByUuidAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid())
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
    public void getComponentByUuidWithRepositoryMetaDataTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("abc");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid())
                .queryParam("includeRepositoryMetaData", true)
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals("MAVEN", json.getJsonObject("repositoryMeta").getString("repositoryType"));
        Assert.assertEquals("org.acme", json.getJsonObject("repositoryMeta").getString("namespace"));
        Assert.assertEquals("abc", json.getJsonObject("repositoryMeta").getString("name"));
        Assert.assertEquals("2.0.0", json.getJsonObject("repositoryMeta").getString("latestVersion"));
        Assert.assertEquals(lastCheck.getTime(), json.getJsonObject("repositoryMeta").getJsonNumber("lastCheck").longValue());
    }

    @Test
    public void getComponentByUuidWithPublishedMetaDataTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        Date published = new Date();
        integrityAnalysis.setUpdatedAt(published);
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_PASSED);
        qm.persist(integrityAnalysis);
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(published);
        integrityMetaComponent.setLastFetch(published);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        RepositoryMetaComponent meta = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta.setLastCheck(lastCheck);
        meta.setNamespace("org.acme");
        meta.setName("abc");
        meta.setLatestVersion("2.0.0");
        meta.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta);
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid())
                .queryParam("includeRepositoryMetaData", true)
                .queryParam("includeIntegrityMetaData", true)
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getString("name"));
        Assert.assertEquals("MAVEN", json.getJsonObject("repositoryMeta").getString("repositoryType"));
        Assert.assertEquals("org.acme", json.getJsonObject("repositoryMeta").getString("namespace"));
        Assert.assertEquals("abc", json.getJsonObject("repositoryMeta").getString("name"));
        Assert.assertEquals("2.0.0", json.getJsonObject("repositoryMeta").getString("latestVersion"));
        Assert.assertEquals(lastCheck.getTime(), json.getJsonObject("repositoryMeta").getJsonNumber("lastCheck").longValue());
        Assert.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonObject("componentMetaInformation").getJsonNumber("publishedDate").longValue() / 1000)).toString());
        Assert.assertEquals(HASH_MATCH_PASSED.toString(), json.getJsonObject("componentMetaInformation").getString("integrityMatchStatus"));
        Assert.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonObject("componentMetaInformation").getJsonNumber("lastFetched").longValue() / 1000)).toString());
    }


    @Test
    public void integrityCheckStatusPassTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        Date published = new Date();
        integrityAnalysis.setUpdatedAt(published);
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_PASSED);
        qm.persist(integrityAnalysis);
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid() + "/integritycheckstatus")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(HASH_MATCH_PASSED.name(), json.getString("md5HashMatchStatus"));
        Assert.assertEquals(HASH_MATCH_PASSED.name(), json.getString("integrityCheckStatus"));
        Assert.assertEquals(HASH_MATCH_PASSED.name(), json.getString("sha512HashMatchStatus"));
        Assert.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonNumber("updatedAt").longValue() / 1000)).toString());
    }

    @Test
    public void integrityCheckStatusFailTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_FAILED);
        Date published = new Date();
        integrityAnalysis.setUpdatedAt(published);
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_FAILED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_FAILED);
        qm.persist(integrityAnalysis);
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid() + "/integritycheckstatus")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(HASH_MATCH_FAILED.name(), json.getString("md5HashMatchStatus"));
        Assert.assertEquals(HASH_MATCH_FAILED.name(), json.getString("integrityCheckStatus"));
        Assert.assertEquals(HASH_MATCH_FAILED.name(), json.getString("sha512HashMatchStatus"));
        Assert.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonNumber("updatedAt").longValue() / 1000)).toString());
    }

    @Test
    public void getIntegrityMetaComponentAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_FAILED);
        integrityAnalysis.setUpdatedAt(new Date());
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_FAILED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_FAILED);
        qm.persist(integrityAnalysis);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid() + "/integritycheckstatus")
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
    public void integrityMetaDataFoundTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/io.micrometer/micrometer-registry-prometheus@1.9.4?type=jar");
        Date published = new Date();
        component = qm.createComponent(component, false);
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(published);
        integrityMetaComponent.setLastFetch(published);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        integrityMetaComponent.setRepositoryUrl("https://repo1.maven.org/maven2/io/micrometer/micrometer-registry-prometheus/1.9.4/micrometer-registry-prometheus-1.9.4.jar");
        integrityMetaComponent.setMd5("45e5bdba87362b16852ec279c254eb57");
        integrityMetaComponent.setSha1("45e5bdba87362b16852ec279c254eb57");
        qm.createIntegrityMetaComponent(integrityMetaComponent);

        Response response = jersey.target(V1_COMPONENT + "/integritymetadata")
                .queryParam("purl", component.getPurl())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("https://repo1.maven.org/maven2/io/micrometer/micrometer-registry-prometheus/1.9.4/micrometer-registry-prometheus-1.9.4.jar", json.getString("repositoryUrl"));
        Assert.assertEquals("45e5bdba87362b16852ec279c254eb57", json.getString("md5"));
        Assert.assertEquals("45e5bdba87362b16852ec279c254eb57", json.getString("sha1"));
        Assert.assertEquals(published.toString(), Date.from(Instant.ofEpochSecond(json.getJsonNumber("publishedAt").longValue() / 1000)).toString());
    }

    @Test
    public void integrityMetaDataNotFoundTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/io.micrometer/micrometer-registry-prometheus@1.9.4?type=jar");
        Date published = new Date();
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/integritymetadata")
                .queryParam("purl", component.getPurl())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void integrityMetaDataInvalidPurlTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/io.micrometer/micrometer-registry-prometheus@1.9.4?type=jar");
        Date published = new Date();
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/integritymetadata")
                .queryParam("purl", "component.getPurl()")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void getComponentByIdentityWithCoordinatesTest() {
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("group", "groupB")
                .queryParam("name", "nameB")
                .queryParam("version", "versionB")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityAclTest() {
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("acme-app-accessible");
        accessibleProject.addAccessTeam(super.team);
        qm.persist(accessibleProject);

        final var accessibleComponent = new Component();
        accessibleComponent.setProject(accessibleProject);
        accessibleComponent.setName("acme-lib");
        qm.persist(accessibleComponent);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("acme-app-inaccessible");
        qm.persist(inaccessibleProject);

        final var inaccessibleComponent = new Component();
        inaccessibleComponent.setProject(inaccessibleProject);
        inaccessibleComponent.setName("acme-lib");
        qm.persist(inaccessibleComponent);

        Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("name", "acme-lib")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final String responseJson = getPlainTextBody(response);
        assertThatJson(responseJson).isArray().hasSize(1);
        assertThatJson(responseJson).inPath("$[0].uuid").isEqualTo(accessibleComponent.getUuid().toString());
    }

    @Test
    public void getDependencyGraphForComponentTestWithRepositoryMetaData() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component1 = new Component();
        component1.setProject(project);
        component1.setName("Component1");
        component1.setVersion("1.0.0");
        component1.setPurl("pkg:maven/org.acme/component1");
        RepositoryMetaComponent meta1 = new RepositoryMetaComponent();
        Date lastCheck = new Date();
        meta1.setLastCheck(lastCheck);
        meta1.setNamespace("org.acme");
        meta1.setName("component1");
        meta1.setLatestVersion("2.0.0");
        meta1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1);
        component1 = qm.createComponent(component1, false);

        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setName("Component1_1");
        component1_1.setVersion("2.0.0");
        component1_1.setPurl("pkg:maven/org.acme/component1_1");
        RepositoryMetaComponent meta1_1 = new RepositoryMetaComponent();
        meta1_1.setLastCheck(lastCheck);
        meta1_1.setNamespace("org.acme");
        meta1_1.setName("component1_1");
        meta1_1.setLatestVersion("3.0.0");
        meta1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1);
        component1_1 = qm.createComponent(component1_1, false);

        Component component1_1_1 = new Component();
        component1_1_1.setProject(project);
        component1_1_1.setName("Component1_1_1");
        component1_1_1.setVersion("3.0.0");
        component1_1_1.setPurl("pkg:maven/org.acme/component1_1_1");
        RepositoryMetaComponent meta1_1_1 = new RepositoryMetaComponent();
        meta1_1_1.setLastCheck(lastCheck);
        meta1_1_1.setNamespace("org.acme");
        meta1_1_1.setName("component1_1_1");
        meta1_1_1.setLatestVersion("4.0.0");
        meta1_1_1.setRepositoryType(RepositoryType.MAVEN);
        qm.persist(meta1_1_1);
        component1_1_1 = qm.createComponent(component1_1_1, false);

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        component1_1.setDirectDependencies("[{\"uuid\":\"" + component1_1_1.getUuid() + "\"}]");

        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component1_1_1.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(200, response.getStatus(), 0);

        Assert.assertTrue(json.get(component1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertEquals("2.0.0", json.get(component1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
        Assert.assertTrue(json.get(component1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertEquals("3.0.0", json.get(component1_1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
        Assert.assertFalse(json.get(component1_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertEquals("4.0.0", json.get(component1_1_1.getUuid().toString()).asJsonObject().get("repositoryMeta").asJsonObject().getString("latestVersion"));
    }

    @Test
    public void getComponentByIdentityWithPurlTest() {
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("purl", "pkg:maven/groupB/nameB@versionB")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityWithCpeTest() {
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("groupA");
        componentA.setName("nameA");
        componentA.setVersion("versionA");
        componentA.setCpe("cpe:2.3:a:groupA:nameA:versionA:*:*:*:*:*:*:*");
        componentA.setPurl("pkg:maven/groupA/nameA@versionA?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("groupB");
        componentB.setName("nameB");
        componentB.setVersion("versionB");
        componentB.setCpe("cpe:2.3:a:groupB:nameB:versionB:*:*:*:*:*:*:*");
        componentB.setPurl("pkg:maven/groupB/nameB@versionB?baz=qux");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("cpe", "cpe:2.3:a:groupB:nameB:versionB")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityWithProjectTest() {
        final Project projectA = qm.createProject("projectA", null, "1.0", null, null, null, null, false);
        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setGroup("group");
        componentA.setName("name");
        componentA.setVersion("version");
        componentA.setPurl("pkg:maven/group/name@version?foo=bar");
        qm.createComponent(componentA, false);

        final Project projectB = qm.createProject("projectB", null, "1.0", null, null, null, null, false);
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setGroup("group");
        componentB.setName("name");
        componentB.setVersion("version");
        componentB.setPurl("pkg:maven/group/name@version?foo=bar");
        componentB = qm.createComponent(componentB, false);

        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("purl", "pkg:maven/group/name@version")
                .queryParam("project", projectB.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(componentB.getUuid().toString());
    }

    @Test
    public void getComponentByIdentityWithProjectWhenProjectDoesNotExistTest() {
        final Response response = jersey.target(V1_COMPONENT + "/identity")
                .queryParam("purl", "pkg:maven/group/name@version")
                .queryParam("project", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("The project could not be found");
    }

    @Test
    public void getComponentByHashTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/hash/" + component.getSha1())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "1");
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("ABC", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getComponentByInvalidHashTest() {
        Response response = jersey.target(V1_COMPONENT + "/hash/c5a8829aa3da800216b933e265dd0b97eb6f9341")
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(response.getHeaderString(TOTAL_COUNT_HEADER), "0");
    }

    @Test
    public void createComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        List<OrganizationalContact> authors = new ArrayList<>();
        authors.add(new OrganizationalContact(){{
            setName("SampleAuthor");
        }});
        component.setAuthors(authors);
        component.setPurl("pkg:maven/org.acme/abc");
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("SampleAuthor" ,json.getJsonArray("authors").getJsonObject(0).getString("name"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(kafkaMockProducer.history()).satisfiesExactlyInAnyOrder(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = KafkaTestUtil.deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo(json.getString("purl"));
                },
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.VULN_ANALYSIS_COMMAND.name());
                    final var command = KafkaTestUtil.deserializeValue(KafkaTopics.VULN_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getUuid()).isEqualTo(json.getString("uuid"));
                }
        );
    }

    @Test
    public void createComponentUpperCaseHashTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component.setPurl("pkg:maven/org.acme/abc");
        component.setSha1("640ab2bae07bedc4c163f679a746f7ab7fb5d1fa".toUpperCase());
        component.setSha256("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25".toUpperCase());
        component.setSha3_256("c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0".toUpperCase());
        component.setSha384("7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3".toUpperCase());
        component.setSha3_384("da73bfcba560692a019f52c37de4d5e3ab49ca39c6a75594e3c39d805388c4de9d0ff3927eb9e197536f5b0b3a515f0a".toUpperCase());
        component.setSha512("c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31".toUpperCase());
        component.setSha3_512("301bb421c971fbb7ed01dcc3a9976ce53df034022ba982b97d0f27d48c4f03883aabf7c6bc778aa7c383062f6823045a6d41b8a720afbb8a9607690f89fbe1a7".toUpperCase());
        component.setMd5("0cbc6611f5540bd0809a388dc95a615b".toUpperCase());
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        Assert.assertEquals(component.getSha1(), json.getString("sha1"));
        Assert.assertEquals(component.getSha256(), json.getString("sha256"));
        Assert.assertEquals(component.getSha3_256(), json.getString("sha3_256"));
        Assert.assertEquals(component.getSha384(), json.getString("sha384"));
        Assert.assertEquals(component.getSha3_384(), json.getString("sha3_384"));
        Assert.assertEquals(component.getSha512(), json.getString("sha512"));
        Assert.assertEquals(component.getSha3_512(), json.getString("sha3_512"));
        Assert.assertEquals(component.getMd5(), json.getString("md5"));
    }

    @Test
    public void createComponentAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "name": "acme-lib"
                        }
                        """));

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
        assertThat(response.getStatus()).isEqualTo(201);
    }

    @Test
    public void updateComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setPurl("pkg:maven/org.acme/abc");
        component.setName("My Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var jsonComponent = new Component();
        jsonComponent.setUuid(component.getUuid());
        jsonComponent.setPurl("pkg:maven/org.acme/abc");
        jsonComponent.setName("My Component");
        jsonComponent.setVersion("1.0");
        jsonComponent.setDescription("Test component");
        var externalReference = new ExternalReference();
        externalReference.setType(org.cyclonedx.model.ExternalReference.Type.WEBSITE);
        externalReference.setUrl("test.com");
        jsonComponent.setExternalReferences(List.of(externalReference));

        Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonComponent, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("My Component", json.getString("name"));
        Assert.assertEquals("1.0", json.getString("version"));
        Assert.assertEquals("Test component", json.getString("description"));
        Assert.assertEquals(1, json.getJsonArray("externalReferences").size());
        assertThat(kafkaMockProducer.history()).satisfiesExactlyInAnyOrder(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name()),
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.REPO_META_ANALYSIS_COMMAND.name());
                    final var command = KafkaTestUtil.deserializeValue(KafkaTopics.REPO_META_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getPurl()).isEqualTo(json.getString("purl"));
                },
                record -> {
                    assertThat(record.topic()).isEqualTo(KafkaTopics.VULN_ANALYSIS_COMMAND.name());
                    final var command = KafkaTestUtil.deserializeValue(KafkaTopics.VULN_ANALYSIS_COMMAND, record);
                    assertThat(command.getComponent().getUuid()).isEqualTo(json.getString("uuid"));
                }
        );
    }

    @Test
    public void updateComponentEmptyNameTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        component.setName(" ");
        Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
    }

    @Test
    public void updateComponentInvalidLicenseExpressionTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        qm.persist(component);

        final var jsonComponent = new Component();
        jsonComponent.setName("acme-lib");
        jsonComponent.setVersion("1.0.0");
        jsonComponent.setLicenseExpression("(invalid");

        final Response response = jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "uuid": "%s",
                          "name": "acme-lib",
                          "version": "1.0.0",
                          "licenseExpression": "(invalid"
                        }
                        """.formatted(component.getUuid()), MediaType.APPLICATION_JSON_TYPE));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).
                isEqualTo("""
                        [
                          {
                            "message": "The license expression must be a valid SPDX expression",
                            "messageTemplate": "The license expression must be a valid SPDX expression",
                            "path": "licenseExpression",
                            "invalidValue": "(invalid"
                          }
                        ]
                        """);
    }

    @Test
    public void updateComponentAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey.target(V1_COMPONENT).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "acme-lib-foobar"
                        }
                        """.formatted(component.getUuid())));

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
    public void deleteComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setUuid(UUID.randomUUID());
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        IntegrityAnalysis analysis = new IntegrityAnalysis();
        analysis.setComponent(component);
        analysis.setIntegrityCheckStatus(HASH_MATCH_UNKNOWN);
        analysis.setMd5HashMatchStatus(HASH_MATCH_UNKNOWN);
        analysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        analysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        analysis.setSha512HashMatchStatus(HASH_MATCH_UNKNOWN);
        analysis.setUpdatedAt(new Date());
        IntegrityAnalysis integrityResponse = qm.persist(analysis);
        Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid().toString())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(204, response.getStatus(), 0);
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(IntegrityAnalysis.class, integrityResponse.getId()));
    }

    @Test
    public void deleteComponentInvalidUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void deleteComponentAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .delete();

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
        assertThat(response.getStatus()).isEqualTo(204);
    }

    @Test
    public void internalComponentIdentificationTest() {
        Response response = jersey.target(V1_COMPONENT + "/internal/identify")
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component1 = new Component();
        component1.setProject(project);
        component1.setName("Component1");
        component1 = qm.createComponent(component1, false);

        Component component1_1 = new Component();
        component1_1.setProject(project);
        component1_1.setName("Component1_1");
        component1_1 = qm.createComponent(component1_1, false);

        Component component1_1_1 = new Component();
        component1_1_1.setProject(project);
        component1_1_1.setName("Component1_1_1");
        component1_1_1 = qm.createComponent(component1_1_1, false);

        Component component2 = new Component();
        component2.setProject(project);
        component2.setName("Component2");
        component2 = qm.createComponent(component2, false);

        Component component2_1 = new Component();
        component2_1.setProject(project);
        component2_1.setName("Component2_1");
        component2_1 = qm.createComponent(component2_1, false);

        Component component2_1_1 = new Component();
        component2_1_1.setProject(project);
        component2_1_1.setName("Component2_1_1");
        component2_1_1 = qm.createComponent(component2_1_1, false);

        Component component2_1_1_1 = new Component();
        component2_1_1_1.setProject(project);
        component2_1_1_1.setName("Component2_1_1");
        component2_1_1_1 = qm.createComponent(component2_1_1_1, false);

        project.setDirectDependencies("[{\"uuid\":\"" + component1.getUuid() + "\"}, {\"uuid\":\"" + component2.getUuid() + "\"}]");
        component1.setDirectDependencies("[{\"uuid\":\"" + component1_1.getUuid() + "\"}]");
        component1_1.setDirectDependencies("[{\"uuid\":\"" + component1_1_1.getUuid() + "\"}]");
        component2.setDirectDependencies("[{\"uuid\":\"" + component2_1.getUuid() + "\"}]");
        component2_1.setDirectDependencies("[{\"uuid\":\"" + component2_1_1.getUuid() + "\"}]");
        component2_1_1.setDirectDependencies("[{\"uuid\":\"" + component2_1_1_1.getUuid() + "\"}]");

        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component1_1_1.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(200, response.getStatus(), 0);

        Assert.assertTrue(json.get(component1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertTrue(json.get(component1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component1_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component2.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component2_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Assert.assertFalse(json.get(component2_1_1.getUuid().toString()).asJsonObject().getBoolean("expandDependencyGraph"));
        Component finalComponent2_1_1_1 = component2_1_1_1;
        Assert.assertThrows(NullPointerException.class, () -> json.get(finalComponent2_1_1_1.getUuid().toString()).asJsonObject().asJsonObject());
    }

    @Test
    public void getDependencyGraphForComponentInvalidProjectUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/project/" + UUID.randomUUID() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentInvalidComponentUuidTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get();
        Assert.assertEquals(404, response.getStatus(), 0);
    }

    @Test
    public void getDependencyGraphForComponentNoDependencyGraphTest() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        Response response = jersey.target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(0, json.size());
    }

    @Test
    public void getDependencyGraphForComponentIsNotComponentOfProject() {
        Project projectWithComponent = qm.createProject("Acme Application", null, null, null, null, null, null, false);
        Component component = new Component();
        component.setProject(projectWithComponent);
        component.setName("My Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        projectWithComponent.setDirectDependencies("[{\"uuid\":\"" + component.getUuid() + "\"}]");
        Project projectWithoutComponent = qm.createProject("Acme Library", null, null, null, null, null, null, false);
        Response responseWithComponent = jersey.target(V1_COMPONENT + "/project/" + projectWithComponent.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject jsonWithComponent = parseJsonObject(responseWithComponent);
        Assert.assertEquals(200, responseWithComponent.getStatus(), 0);
        Assert.assertEquals(1, jsonWithComponent.size());
        Response responseWithoutComponent = jersey.target(V1_COMPONENT + "/project/" + projectWithoutComponent.getUuid() + "/dependencyGraph/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get();
        JsonObject jsonWithoutComponent = parseJsonObject(responseWithoutComponent);
        Assert.assertEquals(200, responseWithoutComponent.getStatus(), 0);
        Assert.assertEquals(0, jsonWithoutComponent.size());
    }

    @Test
    public void getDependencyGraphForComponentAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/project/" + project.getUuid() + "/dependencyGraph/" + component.getUuid()).request()
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
    public void getOccurrencesTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var occurrenceA = new ComponentOccurrence();
        occurrenceA.setComponent(component);
        occurrenceA.setLocation("/foo/bar");
        qm.persist(occurrenceA);

        final var occurrenceB = new ComponentOccurrence();
        occurrenceB.setComponent(component);
        occurrenceB.setLocation("/foo/bar/baz");
        occurrenceB.setLine(5);
        occurrenceB.setOffset(666);
        occurrenceB.setSymbol("someSymbol");
        qm.persist(occurrenceB);

        final Response response = jersey.target(V1_COMPONENT + "/" + component.getUuid() + "/occurrence")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");
        assertThatJson(getPlainTextBody(response))
                .withMatcher("occurrenceIdA", equalTo(occurrenceA.getId().toString()))
                .withMatcher("occurrenceIdB", equalTo(occurrenceB.getId().toString()))
                .isEqualTo(/* language=JSON */ """
                        [
                          {
                            "id": "${json-unit.matches:occurrenceIdA}",
                            "location": "/foo/bar",
                            "createdAt": "${json-unit.any-number}"
                          },
                          {
                            "id": "${json-unit.matches:occurrenceIdB}",
                            "location": "/foo/bar/baz",
                            "line": 5,
                            "offset": 666,
                            "symbol": "someSymbol",
                            "createdAt": "${json-unit.any-number}"
                          }
                        ]
                        """);
    }

    @Test
    public void getOccurrencesComponentNotFoundTest() {
        final Response response = jersey.target(V1_COMPONENT + "/aa684b6f-de53-4249-a2b1-bf16ac458328/occurrence")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 404,
                  "title": "Resource does not exist",
                  "detail": "Component could not be found"
                }
                """);
    }

    @Test
    public void getOccurrencesAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_COMPONENT + "/" + component.getUuid() + "/occurrence")
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
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThatJson(getPlainTextBody(response)).isEqualTo("[]");
    }

}
