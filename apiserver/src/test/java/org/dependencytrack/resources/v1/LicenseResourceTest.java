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
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.License;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

public class LicenseResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(LicenseResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    @Override
    public void before() throws Exception {
        super.before();

        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultLicenses);
    }

    @Test
    public void getLicensesTest() {
        Response response = jersey.target(V1_LICENSE).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals(String.valueOf(738), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(100, json.size());
        Assert.assertNotNull(json.getJsonObject(0).getString("name"));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseText"));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseComments"));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseId"));
    }

    @Test
    public void getLicensesConciseTest() {
        Response response = jersey.target(V1_LICENSE + "/concise").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(738, json.size());
        Assert.assertNotNull(json.getJsonObject(0).getString("name"));
        Assert.assertNull(json.getJsonObject(0).getString("licenseText", null));
        Assert.assertNull(json.getJsonObject(0).getString("licenseComments", null));
        Assert.assertNotNull(json.getJsonObject(0).getString("licenseId"));
    }

    @Test
    public void getLicense() {
        Response response = jersey.target(V1_LICENSE + "/Apache-2.0").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Apache License 2.0", json.getString("name"));
        Assert.assertNotNull(json.getString("licenseText", null));
        Assert.assertNotNull(json.getString("licenseComments", null));
        Assert.assertNotNull(json.getString("licenseId"));
    }

    @Test
    public void getLicenseInvalid() {
        Response response = jersey.target(V1_LICENSE + "/blah").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The license could not be found.", body);
    }

    @Test
    public void createCustomLicense() {
        License license = new License();
        license.setName("Acme Example");
        license.setLicenseId("Acme-Example-License");
        Response response = jersey.target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(license, MediaType.APPLICATION_JSON));
        Assert.assertEquals(201, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assert.assertNotNull(json);
        Assert.assertEquals("Acme Example", json.getString("name"));
        Assert.assertEquals("Acme-Example-License", json.getString("licenseId"));
        Assert.assertFalse(json.getBoolean("isOsiApproved"));
        Assert.assertFalse(json.getBoolean("isFsfLibre"));
        Assert.assertFalse(json.getBoolean("isDeprecatedLicenseId"));
        Assert.assertTrue(json.getBoolean("isCustomLicense"));
        Assert.assertTrue(UuidUtil.isValidUUID(json.getString("uuid")));
    }

    @Test
    public void createCustomLicenseDuplicate() {
        License license = new License();
        license.setName("Apache License 2.0");
        license.setLicenseId("Apache-2.0");
        Response response = jersey.target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(license, MediaType.APPLICATION_JSON));
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("A license with the specified name already exists.", body);
    }

    @Test
    public void createCustomLicenseWithoutLicenseId() {
        License license = new License();
        license.setName("Acme Example");
        Response response = jersey.target(V1_LICENSE)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(license, MediaType.APPLICATION_JSON));
        Assert.assertEquals(400, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
    }

    @Test
    public void deleteCustomLicense() {
        License license = new License();
        license.setLicenseId("Acme-Example-License");
        license.setName("Acme Example");
        license.setCustomLicense(true);
        qm.createCustomLicense(license, false);

        Response response = jersey.target(V1_LICENSE + "/" + license.getLicenseId())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(204, response.getStatus(), 0);
        Assert.assertTrue(license.isCustomLicense());
    }

    @Test
    public void deleteNotCustomLicense() {
        License license1 = new License();
        license1.setLicenseId("Acme-Example-License");
        license1.setName("Acme Example");
        License license2 = qm.createCustomLicense(license1, false);
        license1.setCustomLicense(false);
        Response response = jersey.target(V1_LICENSE + "/" + license1.getLicenseId())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        Assert.assertEquals(409, response.getStatus(), 0);
        Assert.assertFalse(license2.isCustomLicense());
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("Only custom licenses can be deleted.", body);
    }
}
