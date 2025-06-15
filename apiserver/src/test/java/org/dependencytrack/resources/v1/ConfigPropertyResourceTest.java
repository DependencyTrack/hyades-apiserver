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
import alpine.server.filters.AuthenticationFeature;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import java.util.Arrays;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED;
import static org.junit.Assert.assertEquals;

public class ConfigPropertyResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(ConfigPropertyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Test
    public void getConfigPropertiesTest() {
        qm.createConfigProperty("my.group", "my.string", "ABC", IConfigProperty.PropertyType.STRING, "A string");
        qm.createConfigProperty("my.group", "my.integer", "1", IConfigProperty.PropertyType.INTEGER, "A integer");
        qm.createConfigProperty("my.group", "my.password", "password", IConfigProperty.PropertyType.ENCRYPTEDSTRING, "A password");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        assertEquals(3, json.size());
        assertEquals("my.group", json.getJsonObject(0).getString("groupName"));
        assertEquals("my.integer", json.getJsonObject(0).getString("propertyName"));
        assertEquals("1", json.getJsonObject(0).getString("propertyValue"));
        assertEquals("INTEGER", json.getJsonObject(0).getString("propertyType"));
        assertEquals("A integer", json.getJsonObject(0).getString("description"));
        assertEquals("my.group", json.getJsonObject(2).getString("groupName"));
        assertEquals("my.string", json.getJsonObject(2).getString("propertyName"));
        assertEquals("ABC", json.getJsonObject(2).getString("propertyValue"));
        assertEquals("STRING", json.getJsonObject(2).getString("propertyType"));
        assertEquals("A string", json.getJsonObject(2).getString("description"));
        assertEquals("my.group", json.getJsonObject(1).getString("groupName"));
        assertEquals("my.password", json.getJsonObject(1).getString("propertyName"));
        assertEquals("HiddenDecryptedPropertyPlaceholder", json.getJsonObject(1).getString("propertyValue"));
        assertEquals("ENCRYPTEDSTRING", json.getJsonObject(1).getString("propertyType"));
        assertEquals("A password", json.getJsonObject(1).getString("description"));
    }

    @Test
    public void updateConfigPropertyStringTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.string", "ABC", IConfigProperty.PropertyType.STRING, "A string");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("DEF");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals("my.group", json.getString("groupName"));
        assertEquals("my.string", json.getString("propertyName"));
        assertEquals("DEF", json.getString("propertyValue"));
        assertEquals("STRING", json.getString("propertyType"));
        assertEquals("A string", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyBooleanTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.boolean", "false", IConfigProperty.PropertyType.BOOLEAN, "A boolean");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("true");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals("my.group", json.getString("groupName"));
        assertEquals("my.boolean", json.getString("propertyName"));
        assertEquals("true", json.getString("propertyValue"));
        assertEquals("BOOLEAN", json.getString("propertyType"));
        assertEquals("A boolean", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyNumberTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.number", "7.75", IConfigProperty.PropertyType.NUMBER, "A number");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("5.50");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals("my.group", json.getString("groupName"));
        assertEquals("my.number", json.getString("propertyName"));
        assertEquals("5.50", json.getString("propertyValue"));
        assertEquals("NUMBER", json.getString("propertyType"));
        assertEquals("A number", json.getString("description"));
    }

    @Test
    public void updateBadTaskSchedulerCadenceConfigPropertyTest() {
        ConfigProperty property = qm.createConfigProperty(ConfigPropertyConstants.TASK_SCHEDULER_LDAP_SYNC_CADENCE.getGroupName(), "my.cadence", "24", IConfigProperty.PropertyType.INTEGER, "A cadence");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("-2");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        assertEquals("A Task scheduler cadence ("+request.getPropertyName()+") cannot be inferior to one hour.A value of -2 was provided.", body);
    }

    @Test
    public void updateBadIndexConsistencyThresholdConfigPropertyTest() {
        ConfigProperty property = qm.createConfigProperty(ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getGroupName(), ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getPropertyName(), "24", IConfigProperty.PropertyType.INTEGER, ConfigPropertyConstants.SEARCH_INDEXES_CONSISTENCY_CHECK_DELTA_THRESHOLD.getDescription());
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("-1");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(400, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        assertEquals("Lucene index delta threshold ("+request.getPropertyName()+") cannot be inferior to 1 or superior to 100.A value of -1 was provided.", body);
    }

    @Test
    public void updateConfigPropertyUrlTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.url", "http://localhost", IConfigProperty.PropertyType.URL, "A url");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("http://localhost/path");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals("my.group", json.getString("groupName"));
        assertEquals("my.url", json.getString("propertyName"));
        assertEquals("http://localhost/path", json.getString("propertyValue"));
        assertEquals("URL", json.getString("propertyType"));
        assertEquals("A url", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyUuidTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.uuid", "a496cabc-749d-4751-b9e5-3b49b656d018", IConfigProperty.PropertyType.UUID, "A uuid");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("fe03c401-b5a1-4b86-bc3b-1b7a68f0f78d");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals("my.group", json.getString("groupName"));
        assertEquals("my.uuid", json.getString("propertyName"));
        assertEquals("fe03c401-b5a1-4b86-bc3b-1b7a68f0f78d", json.getString("propertyValue"));
        assertEquals("UUID", json.getString("propertyType"));
        assertEquals("A uuid", json.getString("description"));
    }

    @Test
    public void updateConfigPropertyEncryptedStringTest() {
        ConfigProperty property = qm.createConfigProperty("my.group", "my.encryptedString", "aaaaa", IConfigProperty.PropertyType.ENCRYPTEDSTRING, "A encrypted string");
        ConfigProperty request = qm.detach(ConfigProperty.class, property.getId());
        request.setPropertyValue("bbbbb");
        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        assertEquals("my.group", json.getString("groupName"));
        assertEquals("my.encryptedString", json.getString("propertyName"));
        assertEquals("HiddenDecryptedPropertyPlaceholder", json.getString("propertyValue"));
        assertEquals("ENCRYPTEDSTRING", json.getString("propertyType"));
        assertEquals("A encrypted string", json.getString("description"));
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
        assertEquals("risk-score", json.getString("groupName"));
        assertEquals("weight.critical", json.getString("propertyName"));
        assertEquals("8", json.getString("propertyValue"));
        assertEquals("INTEGER", json.getString("propertyType"));
        assertEquals("Critical severity vulnerability weight (between 1-10)", json.getString("description"));
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
        assertEquals(200, response.getStatus(), 0);
        JsonArray json = parseJsonArray(response);
        JsonObject modifiedProp = json.getJsonObject(2);
        Assert.assertNotNull(modifiedProp);
        assertEquals("my.group", modifiedProp.getString("groupName"));
        assertEquals("my.string3", modifiedProp.getString("propertyName"));
        assertEquals("XYZ", modifiedProp.getString("propertyValue"));
        assertEquals("STRING", modifiedProp.getString("propertyType"));
        assertEquals("A string", modifiedProp.getString("description"));
        String body = json.getString(3);
        assertEquals("A Task scheduler cadence ("+prop4.getPropertyName()+") cannot be inferior to one hour.A value of -2 was provided.", body);
    }

    @Test
    public void updateConfigPropertyBomValidationModeTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_MODE.getDescription()
        );

        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.mode",
                          "propertyValue": "ENABLED_FOR_TAGS"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "artifact",
                  "propertyName": "bom.validation.mode",
                  "propertyValue": "ENABLED_FOR_TAGS",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);

        response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.mode",
                          "propertyValue": "foo"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("Value must be any of: ENABLED, DISABLED, ENABLED_FOR_TAGS, DISABLED_FOR_TAGS");
    }

    @Test
    public void updateConfigPropertyBomValidationTagsExclusiveTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE.getDescription()
        );

        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.exclusive",
                          "propertyValue": "[\\"foo\\"]"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "artifact",
                  "propertyName": "bom.validation.tags.exclusive",
                  "propertyValue": "[\\"foo\\"]",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);

        response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.exclusive",
                          "propertyValue": "foo"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("Value must be a valid JSON array of strings");
    }

    @Test
    public void updateConfigPropertyBomValidationTagsInclusiveTest() {
        qm.createConfigProperty(
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getGroupName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getDefaultPropertyValue(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyType(),
                ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE.getDescription()
        );

        Response response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.inclusive",
                          "propertyValue": "[\\"foo\\"]"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "groupName": "artifact",
                  "propertyName": "bom.validation.tags.inclusive",
                  "propertyValue": "[\\"foo\\"]",
                  "propertyType": "STRING",
                  "description": "${json-unit.any-string}"
                }
                """);

        response = jersey.target(V1_CONFIG_PROPERTY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "groupName": "artifact",
                          "propertyName": "bom.validation.tags.inclusive",
                          "propertyValue": "foo"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(getPlainTextBody(response)).isEqualTo("Value must be a valid JSON array of strings");
    }

    @Test
    public void getPublicAllPropertiesTest() {
        for (ConfigPropertyConstants configProperty : ConfigPropertyConstants.values()) {
            String groupName = configProperty.getGroupName();
            String propertyName = configProperty.getPropertyName();
            qm.createConfigProperty(
                    groupName,
                    propertyName,
                    configProperty.getDefaultPropertyValue(),
                    configProperty.getPropertyType(),
                    configProperty.getDescription());

            Response response = jersey.target(V1_CONFIG_PROPERTY + "/public/" + groupName + "/" + propertyName)
                    .request()
                    .header(X_API_KEY, apiKey).get();
            int status = configProperty.getIsPublic() ? 200 : 403;
            assertEquals(status, response.getStatus());
        }
    }
}
