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

import alpine.model.ConfigProperty;
import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED;

public class ConfigPropertyResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ConfigPropertyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Test
    public void getConfigPropertiesTest() {
        qm.createConfigProperty("my.group", "my.string", "ABC", IConfigProperty.PropertyType.STRING, "A string");
        qm.createConfigProperty("my.group", "my.integer", "1", IConfigProperty.PropertyType.INTEGER, "A integer");
        qm.createConfigProperty("my.group", "my.password", "password", IConfigProperty.PropertyType.ENCRYPTEDSTRING, "A password");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(3, json.size());
        Assert.assertEquals("my.group", json.getJsonObject(0).getString("groupName"));
        Assert.assertEquals("my.integer", json.getJsonObject(0).getString("propertyName"));
        Assert.assertEquals("1", json.getJsonObject(0).getString("propertyValue"));
        Assert.assertEquals("INTEGER", json.getJsonObject(0).getString("propertyType"));
        Assert.assertEquals("A integer", json.getJsonObject(0).getString("description"));
        Assert.assertEquals("my.group", json.getJsonObject(2).getString("groupName"));
        Assert.assertEquals("my.string", json.getJsonObject(2).getString("propertyName"));
        Assert.assertEquals("ABC", json.getJsonObject(2).getString("propertyValue"));
        Assert.assertEquals("STRING", json.getJsonObject(2).getString("propertyType"));
        Assert.assertEquals("A string", json.getJsonObject(2).getString("description"));
        Assert.assertEquals("my.group", json.getJsonObject(1).getString("groupName"));
        Assert.assertEquals("my.password", json.getJsonObject(1).getString("propertyName"));
        Assert.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getJsonObject(1).getString("propertyValue"));
        Assert.assertEquals("ENCRYPTEDSTRING", json.getJsonObject(1).getString("propertyType"));
        Assert.assertEquals("A password", json.getJsonObject(1).getString("description"));
    }

    @Test
    public void updateConfigPropertyStringTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.string", "ABC", IConfigProperty.PropertyType.STRING, "A string");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("DEF");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("my.group", json.getString("groupName"));
        Assert.assertEquals("my.string", json.getString("propertyName"));
        Assert.assertEquals("DEF", json.getString("propertyValue"));
        Assert.assertEquals("STRING", json.getString("propertyType"));
        Assert.assertEquals("A string", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyBooleanTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.boolean", "false", IConfigProperty.PropertyType.BOOLEAN, "A boolean");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("true");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("my.group", json.getString("groupName"));
        Assert.assertEquals("my.boolean", json.getString("propertyName"));
        Assert.assertEquals("true", json.getString("propertyValue"));
        Assert.assertEquals("BOOLEAN", json.getString("propertyType"));
        Assert.assertEquals("A boolean", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyNumberTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.number", "7.75", IConfigProperty.PropertyType.NUMBER, "A number");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("5.50");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("my.group", json.getString("groupName"));
        Assert.assertEquals("my.number", json.getString("propertyName"));
        Assert.assertEquals("5.50", json.getString("propertyValue"));
        Assert.assertEquals("NUMBER", json.getString("propertyType"));
        Assert.assertEquals("A number", json.getString("description"));
    }

    @Test
    public void updateBadTaskSchedulerCadenceConfigPropertyTest() {
        ConfigProperty property = qm.createConfigProperty(ConfigPropertyConstants.TASK_SCHEDULER_LDAP_SYNC_CADENCE.getGroupName(), "my.cadence", "24", IConfigProperty.PropertyType.INTEGER, "A cadence");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("-2");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("A Task scheduler cadence ("+request.getPropertyName()+") cannot be inferior to one hour.A value of -2 was provided.", body);
    }

    @Test
    public void updateBadIndexConsistencyThresholdConfigPropertyTest() {
        ConfigProperty property = qm.createConfigProperty(ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getGroupName(), ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getPropertyName(), "24", IConfigProperty.PropertyType.INTEGER, ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getDescription());
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("-1");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("Lucene index delta threshold ("+request.getPropertyName()+") cannot be inferior to 1 or superior to 100.A value of -1 was provided.", body);
    }

    @Test
    public void updateConfigPropertyUrlTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.url", "http://localhost", IConfigProperty.PropertyType.URL, "A url");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("http://localhost/path");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("my.group", json.getString("groupName"));
        Assert.assertEquals("my.url", json.getString("propertyName"));
        Assert.assertEquals("http://localhost/path", json.getString("propertyValue"));
        Assert.assertEquals("URL", json.getString("propertyType"));
        Assert.assertEquals("A url", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyUuidTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.uuid", "a496cabc-749d-4751-b9e5-3b49b656d018", IConfigProperty.PropertyType.UUID, "A uuid");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("fe03c401-b5a1-4b86-bc3b-1b7a68f0f78d");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("my.group", json.getString("groupName"));
        Assert.assertEquals("my.uuid", json.getString("propertyName"));
        Assert.assertEquals("fe03c401-b5a1-4b86-bc3b-1b7a68f0f78d", json.getString("propertyValue"));
        Assert.assertEquals("UUID", json.getString("propertyType"));
        Assert.assertEquals("A uuid", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyEncryptedStringTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.encryptedString", "aaaaa", IConfigProperty.PropertyType.ENCRYPTEDSTRING, "A encrypted string");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("bbbbb");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("my.group", json.getString("groupName"));
        Assert.assertEquals("my.encryptedString", json.getString("propertyName"));
        Assert.assertEquals("HiddenDecryptedPropertyPlaceholder", json.getString("propertyValue"));
        Assert.assertEquals("ENCRYPTEDSTRING", json.getString("propertyType"));
        Assert.assertEquals("A encrypted string", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyReadOnlyTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getGroupName(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getPropertyName(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getDefaultPropertyValue(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getPropertyType(),
                ConfigPropertyConstants.INTERNAL_CLUSTER_ID.getDescription()
        );

        final Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity("""
                        {
                          "groupName": "internal",
                          "propertyName": "cluster.id",
                          "propertyValue": "foobar"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("The property internal.cluster.id can not be modified");
    }

    @Test
    public void testRiskScoreInvalid(){
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_CRITICAL.getGroupName(), 
                CUSTOM_RISK_SCORE_CRITICAL.getPropertyName(), 
                CUSTOM_RISK_SCORE_CRITICAL.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_CRITICAL.getPropertyType(), 
                CUSTOM_RISK_SCORE_CRITICAL.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_HIGH.getGroupName(), 
                CUSTOM_RISK_SCORE_HIGH.getPropertyName(), 
                CUSTOM_RISK_SCORE_HIGH.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_HIGH.getPropertyType(), 
                CUSTOM_RISK_SCORE_HIGH.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_MEDIUM.getGroupName(), 
                CUSTOM_RISK_SCORE_MEDIUM.getPropertyName(), 
                CUSTOM_RISK_SCORE_MEDIUM.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_MEDIUM.getPropertyType(), 
                CUSTOM_RISK_SCORE_MEDIUM.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_LOW.getGroupName(), 
                CUSTOM_RISK_SCORE_LOW.getPropertyName(), 
                CUSTOM_RISK_SCORE_LOW.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_LOW.getPropertyType(), 
                CUSTOM_RISK_SCORE_LOW.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_UNASSIGNED.getGroupName(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyType(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getDescription()
            );

        final Response response = jersey.target(V1_CONFIG_PROPERTY).request()
        .header(X_API_KEY, apiKey)
        .post(Entity.entity("""
                {
                  "groupName": "risk-score",
                  "propertyName": "weight.critical",
                  "propertyValue": "11"
                }
                """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("Risk score \"weight.critical\" must be between 1 and 10. An invalid value of 11 was provided.");
    }

    @Test
    public void testRiskScoreUpdate(){
        qm.createConfigProperty(
                CUSTOM_RISK_SCORE_CRITICAL.getGroupName(), 
                CUSTOM_RISK_SCORE_CRITICAL.getPropertyName(), 
                CUSTOM_RISK_SCORE_CRITICAL.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_CRITICAL.getPropertyType(), 
                CUSTOM_RISK_SCORE_CRITICAL.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_HIGH.getGroupName(), 
                CUSTOM_RISK_SCORE_HIGH.getPropertyName(), 
                CUSTOM_RISK_SCORE_HIGH.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_HIGH.getPropertyType(), 
                CUSTOM_RISK_SCORE_HIGH.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_MEDIUM.getGroupName(), 
                CUSTOM_RISK_SCORE_MEDIUM.getPropertyName(), 
                CUSTOM_RISK_SCORE_MEDIUM.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_MEDIUM.getPropertyType(), 
                CUSTOM_RISK_SCORE_MEDIUM.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_LOW.getGroupName(), 
                CUSTOM_RISK_SCORE_LOW.getPropertyName(), 
                CUSTOM_RISK_SCORE_LOW.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_LOW.getPropertyType(), 
                CUSTOM_RISK_SCORE_LOW.getDescription()
            );
            qm.createConfigProperty(
                CUSTOM_RISK_SCORE_UNASSIGNED.getGroupName(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getDefaultPropertyValue(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyType(), 
                CUSTOM_RISK_SCORE_UNASSIGNED.getDescription()
            );

        final Response response = jersey.target(V1_CONFIG_PROPERTY).request()
        .header(X_API_KEY, apiKey)
        .post(Entity.entity("""
                {
                  "groupName": "risk-score",
                  "propertyName": "weight.critical",
                  "propertyValue": "8"
                }
                """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(200);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("risk-score", json.getString("groupName"));
        Assert.assertEquals("weight.critical", json.getString("propertyName"));
        Assert.assertEquals("8", json.getString("propertyValue"));
        Assert.assertEquals("INTEGER", json.getString("propertyType"));
        Assert.assertEquals("Critical severity vulnerability weight (between 1-10)", json.getString("description"));
    }

    @Test
    public void updateConfigPropertiesAggregateTest() {
        ConfigProperty prop1 = qm.createConfigProperty("my.group", "my.string1", "ABC", IConfigProperty.PropertyType.STRING, "A string");
        ConfigProperty prop2 = qm.createConfigProperty("my.group", "my.string2", "DEF", IConfigProperty.PropertyType.STRING, "A string");
        ConfigProperty prop3 = qm.createConfigProperty("my.group", "my.string3", "GHI", IConfigProperty.PropertyType.STRING, "A string");
        ConfigProperty prop4 = qm.createConfigProperty(ConfigPropertyConstants.TASK_SCHEDULER_LDAP_SYNC_CADENCE.getGroupName(), "my.cadence", "1", IConfigProperty.PropertyType.INTEGER, "A cadence");
        prop1 = qm.detach(ConfigProperty.class, prop1.getId());
        prop2 = qm.detach(ConfigProperty.class, prop2.getId());
        prop3 = qm.detach(ConfigProperty.class, prop3.getId());
        prop4 = qm.detach(ConfigProperty.class, prop4.getId());
        prop3.setPropertyValue("XYZ");
        prop4.setPropertyValue("-2");
        Response response = jersey.target(V1_CONFIG_PROPERTY+"/aggregate").request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(Arrays.asList(prop1, prop2, prop3, prop4), MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonArray json = parseJsonArray(response);
        JsonObject modifiedProp = json.getJsonObject(2);
        Assert.assertNotNull(modifiedProp);
        Assert.assertEquals("my.group", modifiedProp.getString("groupName"));
        Assert.assertEquals("my.string3", modifiedProp.getString("propertyName"));
        Assert.assertEquals("XYZ", modifiedProp.getString("propertyValue"));
        Assert.assertEquals("STRING", modifiedProp.getString("propertyType"));
        Assert.assertEquals("A string", modifiedProp.getString("description"));
        String body = json.getString(3);
        Assert.assertEquals("A Task scheduler cadence ("+prop4.getPropertyName()+") cannot be inferior to one hour.A value of -2 was provided.", body);
    }

}
