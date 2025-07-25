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

import alpine.model.IConfigProperty.PropertyType;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectProperty;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class ProjectPropertyResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ProjectPropertyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Test
    public void getPropertiesTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, "Test Property 1");
        qm.createProjectProperty(project, "mygroup", "prop2", "value2", PropertyType.ENCRYPTEDSTRING, "Test Property 2");
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(2, json.size());
        Assert.assertEquals("mygroup", json.getJsonObject(0).getString("groupName"));
        Assert.assertEquals("prop1", json.getJsonObject(0).getString("propertyName"));
        Assert.assertEquals("value1", json.getJsonObject(0).getString("propertyValue"));
        Assert.assertEquals("STRING", json.getJsonObject(0).getString("propertyType"));
        Assert.assertEquals("Test Property 1", json.getJsonObject(0).getString("description"));
        Assert.assertEquals("mygroup", json.getJsonObject(1).getString("groupName"));
        Assert.assertEquals("prop2", json.getJsonObject(1).getString("propertyName"));
        Assert.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getJsonObject(1).getString("propertyValue"));
        Assert.assertEquals("ENCRYPTEDSTRING", json.getJsonObject(1).getString("propertyType"));
        Assert.assertEquals("Test Property 2", json.getJsonObject(1).getString("description"));
    }

    @Test
    public void getPropertiesInvalidTest() {
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getPropertiesAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
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
    public void createPropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("mygroup", json.getString("groupName"));
        Assert.assertEquals("prop1", json.getString("propertyName"));
        Assert.assertEquals("value1", json.getString("propertyValue"));
        Assert.assertEquals("STRING", json.getString("propertyType"));
        Assert.assertEquals("Test Property 1", json.getString("description"));
    }

    @Test
    public void createPropertyEncryptedTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.ENCRYPTEDSTRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + project.getUuid().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("mygroup", json.getString("groupName"));
        Assert.assertEquals("prop1", json.getString("propertyName"));
        Assert.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getString("propertyValue"));
        Assert.assertEquals("ENCRYPTEDSTRING", json.getString("propertyType"));
        Assert.assertEquals("Test Property 1", json.getString("description"));
    }

    @Test
    public void createPropertyDuplicateTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.close();
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("A property with the specified project/group/name combination already exists.", body);
    }

    @Test
    public void createPropertyInvalidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID() + "/property").request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void createPropertyAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "baz",
                          "propertyType": "STRING"
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
    public void updatePropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        String uuid = project.getUuid().toString();
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, null);
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        property.setPropertyValue("updatedValue");
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("mygroup", json.getString("groupName"));
        Assert.assertEquals("prop1", json.getString("propertyName"));
        Assert.assertEquals("updatedValue", json.getString("propertyValue"));
        Assert.assertEquals("STRING", json.getString("propertyType"));
    }

    @Test
    public void updatePropertyInvalidTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("mygroup");
        property.setPropertyName("prop1");
        property.setPropertyValue("value1");
        property.setPropertyType(PropertyType.STRING);
        property.setDescription("Test Property 1");
        Response response = jersey.target(V1_PROJECT + "/" + UUID.randomUUID().toString() + "/property").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(property, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void updatePropertyAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar",
                          "propertyValue": "qux",
                          "propertyType": "STRING"
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
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void deletePropertyTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        ProjectProperty property = qm.createProjectProperty(project, "mygroup", "prop1", "value1", PropertyType.STRING, null);
        String uuid = project.getUuid().toString();
        qm.getPersistenceManager().detachCopy(property);
        qm.close();
        Response response = jersey.target(V1_PROJECT + "/" + uuid + "/property").request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true) // HACK
                .method("DELETE", Entity.entity(property, MediaType.APPLICATION_JSON)); // HACK
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deletePropertyAclTest() {
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var property = new ProjectProperty();
        property.setProject(project);
        property.setGroupName("foo");
        property.setPropertyName("bar");
        property.setPropertyValue("baz");
        property.setPropertyType(PropertyType.STRING);
        qm.persist(property);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_PROJECT + "/" + project.getUuid() + "/property")
                .request()
                .header(X_API_KEY, apiKey)
                .property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true)
                .method("DELETE", Entity.json(/* language=JSON */ """
                        {
                          "groupName": "foo",
                          "propertyName": "bar"
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
        assertThat(response.getStatus()).isEqualTo(204);
    }

}
