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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.apache.http.HttpStatus;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.event.kafka.KafkaTopics;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.CryptoAlgorithmProperties;
import org.dependencytrack.model.CryptoAssetProperties;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import alpine.common.util.UuidUtil;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class CryptoAssetsResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(CryptoAssetsResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));


    private Component getTestCryptoAsset() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setClassifier(Classifier.CRYPTOGRAPHIC_ASSET);

        CryptoAlgorithmProperties cap = new CryptoAlgorithmProperties();
        cap.setPrimitive(Primitive.AE);
        cap.setParameterSetIdentifier("128");

        CryptoAssetProperties cp = new CryptoAssetProperties();
        cp.setAssetType(AssetType.ALGORITHM);
        cp.setAlgorithmProperties(cap);

        component.setCryptoAssetProperties(cp);
        return qm.createComponent(component, false);
    }

    @Test
    public void getCryptoAssetByUuidTest() {
        Component component = getTestCryptoAsset();
        Response response = jersey.target(V1_CRYPTO + "/" + component.getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(component.getName(), json.getString("name"));
        Assert.assertEquals(component.getClassifier(), Classifier.valueOf(json.getString("classifier")));
    }

    @Test
    public void getCryptoAssetByInvalidUuidTest() {
        Response response = jersey.target(V1_CRYPTO + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The crypto asset could not be found.", body);
    }

    @Test
    public void getCryptoAssetsByProjectTest() {
        Component component = getTestCryptoAsset();
        Response response = jersey.target(V1_CRYPTO + "/project/" + component.getProject().getUuid())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray jsonArray = parseJsonArray(response);
        Assert.assertNotNull(jsonArray);
        JsonObject json = jsonArray.getFirst().asJsonObject();
        Assert.assertEquals(component.getName(), json.getString("name"));
        Assert.assertEquals(component.getClassifier(), Classifier.valueOf(json.getString("classifier")));
    }
    
    @Test
    public void getCryptoAssetsByInvalidProjectTest() {
        Response response = jersey.target(V1_CRYPTO + "/project/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getCryptoByIdentityTest() {
        Component component = getTestCryptoAsset();
        final Response response = jersey.target(V1_CRYPTO + "/identity")
                .queryParam("assetType", AssetType.ALGORITHM.toString())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).hasSize(1);

        final JsonObject jsonComponent = json.getJsonObject(0);
        assertThat(jsonComponent).isNotNull();
        assertThat(jsonComponent.getString("uuid")).isEqualTo(component.getUuid().toString());
    }

    @Test
    public void createCryptoAssetTest() {
        Component component = getTestCryptoAsset();
        Response response = jersey.target(V1_CRYPTO + "/project/" + component.getProject().getUuid()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(component.getName(), json.getString("name"));
        Assert.assertEquals(component.getClassifier(), Classifier.valueOf(json.getString("classifier")));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name())
        );
    }

    @Test
    public void createCryptoAssetsInvalidProjectTest() {
        Component component = getTestCryptoAsset();
        Response response = jersey.target(V1_CRYPTO + "/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(component, MediaType.APPLICATION_JSON));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void updateCryptoAssetInvalidClassifierTest() {
        Component component = getTestCryptoAsset();
        var jsonComponent = new Component();
        jsonComponent.setUuid(component.getUuid());
        jsonComponent.setName(component.getName());
        Response response = jersey.target(V1_CRYPTO).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonComponent, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The component you provided is not a crypto asset", body);
    }

    @Test
    public void updateCryptoAssetNoCryptoTest() {
        Component component = getTestCryptoAsset();
        var jsonComponent = new Component();
        jsonComponent.setUuid(component.getUuid());
        jsonComponent.setName(component.getName());
        jsonComponent.setClassifier(component.getClassifier());
        Response response = jersey.target(V1_CRYPTO).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonComponent, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("No data for crypto asset properties provided", body);
    }

    @Test
    public void updateCryptoAssetTest() {
        Component component = getTestCryptoAsset();
        var jsonComponent = new Component();
        jsonComponent.setUuid(component.getUuid());
        jsonComponent.setName(component.getName());
        jsonComponent.setClassifier(component.getClassifier());
        jsonComponent.setCryptoAssetProperties(component.getCryptoAssetProperties());
        Response response = jersey.target(V1_CRYPTO).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonComponent, MediaType.APPLICATION_JSON));
        Assert.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertEquals(jsonComponent.getName(), json.getString("name"));
        Assert.assertEquals(component.getClassifier(), Classifier.valueOf(json.getString("classifier")));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(kafkaMockProducer.history()).satisfiesExactly(
                record -> assertThat(record.topic()).isEqualTo(KafkaTopics.NOTIFICATION_PROJECT_CREATED.name())
        );
    }

    @Test
    public void updateCryptoAssetInvalidUUIDTest() {
        Component component = getTestCryptoAsset();
        var jsonComponent = new Component();
        jsonComponent.setUuid(UUID.randomUUID());
        jsonComponent.setName(component.getName());
        jsonComponent.setClassifier(component.getClassifier());
        jsonComponent.setCryptoAssetProperties(component.getCryptoAssetProperties());
        Response response = jersey.target(V1_CRYPTO).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(jsonComponent, MediaType.APPLICATION_JSON));
        Assert.assertEquals(404, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The UUID of the component could not be found.", body);
    }

    @Test
    public void deleteCryptoAssetTest() {
        Component component = getTestCryptoAsset();
        Response response = jersey.target(V1_CRYPTO + "/" + component.getUuid().toString())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(204, response.getStatus(), 0);
    }

    @Test
    public void deleteCryptoAssetInvalidUUIDTest() {
        Response response = jersey.target(V1_COMPONENT + "/" + UUID.randomUUID())
                .request().header(X_API_KEY, apiKey).delete();
        Assert.assertEquals(404, response.getStatus(), 0);
    }
}
