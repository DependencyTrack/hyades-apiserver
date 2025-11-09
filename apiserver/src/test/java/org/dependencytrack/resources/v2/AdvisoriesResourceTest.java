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
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Advisory;
import org.junit.ClassRule;
import org.junit.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AdvisoriesResource}.
 *
 * @author Christian Banse
 * @since 5.7.0
 */
public class AdvisoriesResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(new ResourceConfig());

    @Test
    public void testListAdvisories() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        // Create test advisories
        final Advisory advisory1 = new Advisory();
        advisory1.setTitle("Test Advisory 1");
        advisory1.setUrl("https://example.com/advisory1");
        advisory1.setContent("{\"test\":\"content1\"}");
        advisory1.setLastFetched(Instant.now());
        advisory1.setPublisher("publisher1");
        advisory1.setName("ADV-001");
        advisory1.setVersion("1.0");
        advisory1.setFormat("CSAF");
        advisory1.setSeen(true);
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
        advisory2.setSeen(false);
        qm.synchronizeAdvisory(advisory2);

        // Test listing all advisories
        Response response = jersey.target("/advisories")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");

        JsonObject json = parseJsonObject(response);
        JsonArray advisories = json.getJsonArray("advisories");
        assertThat(advisories).hasSize(2);
        assertThat(advisories.getJsonObject(0).getString("title"))
                .isEqualTo("Test Advisory 1");
        assertThat(advisories.getJsonObject(1).getString("title"))
                .isEqualTo("Test Advisory 2");
    }

    @Test
    public void testListAdvisoriesWithFormatFilter() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

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
        csafAdvisory.setSeen(true);
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
        vexAdvisory.setSeen(false);
        qm.synchronizeAdvisory(vexAdvisory);

        // Test filtering by CSAF format
        Response response = jersey.target("/advisories")
                .queryParam("format", "CSAF")
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        JsonObject json = parseJsonObject(response);
        JsonArray advisories = json.getJsonArray("advisories");
        assertThat(advisories).hasSize(1);
        assertThat(advisories.getJsonObject(0).getString("title"))
                .isEqualTo("CSAF Advisory");
        assertThat(advisories.getJsonObject(0).getString("format"))
                .isEqualTo("CSAF");
    }

    @Test
    public void testMarkAdvisoryAsSeen() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS_UPDATE);

        // Create an unseen advisory
        final Advisory advisory = new Advisory();
        advisory.setTitle("Unseen Advisory");
        advisory.setUrl("https://example.com/advisory");
        advisory.setContent("{\"test\":\"content\"}");
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher("publisher");
        advisory.setName("ADV-001");
        advisory.setVersion("1.0");
        advisory.setFormat("CSAF");
        advisory.setSeen(false);
        qm.synchronizeAdvisory(advisory);

        final long advisoryId = advisory.getId();

        // Mark as seen
        Response response = jersey.target("/advisories/seen/" + advisoryId)
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        assertThat(json.getString("title")).isEqualTo("Unseen Advisory");
        assertThat(json.getBoolean("seen")).isTrue();
    }

    @Test
    public void testGetAdvisoryById() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS_READ);

        // Create an advisory
        final Advisory advisory = new Advisory();
        advisory.setTitle("Single Advisory");
        advisory.setUrl("https://example.com/single");
        advisory.setContent("{\"test\":\"single\"}");
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher("publisher");
        advisory.setName("ADV-SINGLE");
        advisory.setVersion("1.0");
        advisory.setFormat("CSAF");
        advisory.setSeen(true);
        qm.synchronizeAdvisory(advisory);

        final long advisoryId = advisory.getId();

        // Retrieve the advisory by id
        Response response = jersey.target("/advisories/" + advisoryId)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);

        JsonObject json = parseJsonObject(response);
        // The API wraps the advisory under 'entity' in GetAdvisoryResponse
        JsonObject entity = json.getJsonObject("entity");
        assertThat(entity.getString("title")).isEqualTo("Single Advisory");
        assertThat(entity.getString("name")).isEqualTo("ADV-SINGLE");
        assertThat(entity.getString("format")).isEqualTo("CSAF");
        assertThat(entity.getBoolean("seen")).isTrue();
    }

    @Test
    public void testGetAdvisoryNotFound() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS_READ);

        // Try to retrieve a non-existent advisory
        try (Response response = jersey.target("/advisories/999999")
                .request()
                .header(X_API_KEY, apiKey)
                .get()) {
            assertThat(response.getStatus()).isEqualTo(404);
        }
    }

    @Test
    public void testDeleteAdvisory() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS_UPDATE);

        // Create an advisory to delete
        final Advisory advisory = new Advisory();
        advisory.setTitle("Advisory to Delete");
        advisory.setUrl("https://example.com/advisory");
        advisory.setContent("{\"test\":\"content\"}");
        advisory.setLastFetched(Instant.now());
        advisory.setPublisher("publisher");
        advisory.setName("ADV-DEL");
        advisory.setVersion("1.0");
        advisory.setFormat("CSAF");
        advisory.setSeen(false);
        qm.synchronizeAdvisory(advisory);

        final long advisoryId = advisory.getId();

        // Delete the advisory
        Response response = jersey.target("/advisories/" + advisoryId)
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);

        // Verify it's deleted by checking the count instead of querying the object directly
        // to avoid JDOObjectNotFoundException
        long count = (Long) qm.getPersistenceManager()
                .newQuery("SELECT count(id) FROM " + Advisory.class.getName() + " WHERE id == :id")
                .execute(advisoryId);
        assertThat(count).isEqualTo(0);
    }

    @Test
    public void testDeleteAdvisoryNotFound() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS_UPDATE);

        // Try to delete a non-existent advisory
        Response response = jersey.target("/advisories/999999")
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(404);
    }
}
