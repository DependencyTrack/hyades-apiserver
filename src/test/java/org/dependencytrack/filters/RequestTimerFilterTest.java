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
package org.dependencytrack.filters;

import alpine.Config;
import alpine.common.metrics.Metrics;
import org.dependencytrack.JerseyTestRule;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.assertj.core.api.Assertions.assertThat;

public class RequestTimerFilterTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(TestResource.class)
                    .register(RequestTimerFilter.class));

    @Rule
    public EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @BeforeClass
    public static void beforeClass() {
        Config.enableUnitTests();
    }

    @Before
    public void before() {
        environmentVariables.set("ALPINE_METRICS_ENABLED", "true");
    }

    @Test
    public void test() {
        final Response response = jersey.target("/foo/123/baz/321")
                .request()
                .get();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(Metrics.getRegistry().scrape()).contains("""
                http_server_requests_seconds_bucket{method="GET",path="/foo/{bar}/baz/{qux}",status="204"\
                """);
    }

    @Path("/foo/{bar}")
    public static class TestResource {

        @GET
        @Path("baz/{qux}")
        @Produces(MediaType.APPLICATION_JSON)
        public Response get(@PathParam("bar") String bar, @PathParam("qux") String qux) {
            return Response.noContent().build();
        }

    }

}