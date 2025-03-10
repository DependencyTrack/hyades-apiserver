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
package org.dependencytrack.integrations.gitlab;

import alpine.Config;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.github.tomakehurst.wiremock.stubbing.Scenario;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.http.HttpHeaders;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import static org.testcontainers.shaded.org.apache.commons.io.IOUtils.resourceToString;

public class GitLabClientTest {

    @BeforeClass
    public static void beforeClass() {
        Config.enableUnitTests();
    }

    @AfterClass
    public static void after() {
        KafkaProducerInitializer.tearDown();
    }

    @Rule
    public WireMockRule wireMockRule = new WireMockRule();

    @Test
    public void testGetGitLabProjects() throws URISyntaxException, IOException {
        String accessToken = "TEST_ACCESS_TOKEN";

        String page1Result = resourceToString("/unit/gitlab-api-getgitlabprojects-response-page-1.json",
                StandardCharsets.UTF_8);
        String page2Result = resourceToString("/unit/gitlab-api-getgitlabprojects-response-page-2.json",
                StandardCharsets.UTF_8);

        WireMock.stubFor(WireMock.post("/api/graphql")
                .inScenario("test-get-gitlab-projects")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(WireMock.ok().withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withBody(page1Result))
                .willSetStateTo("second-page"));

        WireMock.stubFor(WireMock.post("/api/graphql")
                .inScenario("test-get-gitlab-projects")
                .whenScenarioStateIs("second-page")
                .willReturn(WireMock.ok().withHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .withBody(page2Result))
                .willSetStateTo("Finished"));

        final var configMock = mock(Config.class);

        when(configMock.getProperty(eq(Config.AlpineKey.OIDC_ISSUER))).thenReturn(wireMockRule.baseUrl());

        GitLabClient gitLabClient = new GitLabClient(accessToken, configMock);

        List<GitLabProject> gitLabProjects = gitLabClient.getGitLabProjects();

        List<String> actualProjectPaths = new ArrayList<>();
        for (var project : gitLabProjects)
            actualProjectPaths.add(project.getFullPath());

        List<String> expectedProjectPaths = Arrays.asList(
                "test-group/test-subgroup/test-project-1",
                "test-group/test-subgroup/test-project-2",
                "test-group/test-subgroup-2/test-project-3",
                "test-group/test-subgroup-2/test-project-4");

        Assert.assertEquals(actualProjectPaths, expectedProjectPaths);
    }

}
