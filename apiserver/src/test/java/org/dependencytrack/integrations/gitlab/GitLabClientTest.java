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
import jakarta.ws.rs.core.MediaType;
import net.minidev.json.JSONArray;

import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

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
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.kafka.KafkaProducerInitializer;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import static org.testcontainers.shaded.org.apache.commons.io.IOUtils.resourceToString;

public class GitLabClientTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule();

    @BeforeClass
    public static void beforeClass() {
        Config.enableUnitTests();
    }

    @AfterClass
    public static void after() {
        KafkaProducerInitializer.tearDown();
    }

    @Test
    public void testConstructorWithAccessToken() {
        String accessToken = "my-access-token";
        GitLabClient client = new GitLabClient(accessToken);
        Assert.assertNotNull(client);
    }

    @Test
    public void testConstructorWithAccessTokenAndConfig() {
        String accessToken = "my-access-token";
        Config config = Config.getInstance();
        GitLabClient client = new GitLabClient(accessToken, config, null, false);
        Assert.assertNotNull(client);
        Assert.assertEquals("Dependency-Track", client.getConfig().getApplicationName());
    }

    @Test
    public void testGetGitLabProjects() throws URISyntaxException, IOException {
        String accessToken = "TEST_ACCESS_TOKEN";

        String page1Result = resourceToString("/unit/gitlab-api-getgitlabprojects-response-page-1.json",
                StandardCharsets.UTF_8);
        String page2Result = resourceToString("/unit/gitlab-api-getgitlabprojects-response-page-2.json",
                StandardCharsets.UTF_8);

        stubFor(post(urlPathEqualTo("/api/graphql"))
                .inScenario("test-get-gitlab-projects")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(ok().withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody(page1Result))
                .willSetStateTo("second-page"));

        stubFor(post(urlPathEqualTo("/api/graphql"))
                .inScenario("test-get-gitlab-projects")
                .whenScenarioStateIs("second-page")
                .willReturn(ok().withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody(page2Result))
                .willSetStateTo("Finished"));

        final var configMock = mock(Config.class);

        when(configMock.getProperty(eq(Config.AlpineKey.OIDC_ISSUER))).thenReturn(wireMockRule.baseUrl());

        GitLabClient gitLabClient = new GitLabClient(accessToken, configMock, null, false);

        List<GitLabProject> gitLabProjects = gitLabClient.getGitLabProjects();

        Assert.assertNotNull(gitLabProjects);
        Assert.assertEquals(4, gitLabProjects.size());

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

    @Test
    public void testGetGitLabProjectsWithTopics() throws IOException, URISyntaxException {
        String accessToken = "TEST_ACCESS_TOKEN";

        String result = resourceToString("/unit/gitlab-api-getgitlabprojects-topics-response.json",
                StandardCharsets.UTF_8);

        stubFor(post(urlPathEqualTo("/api/graphql"))
                .willReturn(ok().withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody(result)));

        final var configMock = mock(Config.class);

        when(configMock.getProperty(eq(Config.AlpineKey.OIDC_ISSUER))).thenReturn(wireMockRule.baseUrl());
        List<String> topics = Arrays.asList("topic1");

        GitLabClient gitLabClient = new GitLabClient(accessToken, configMock, topics, false);

        List<GitLabProject> gitLabProjects = gitLabClient.getGitLabProjects();

        Assert.assertNotNull(gitLabProjects);
        Assert.assertEquals(1, gitLabProjects.size());

        Assert.assertEquals("project/with/topic", gitLabProjects.get(0).getFullPath());
    }

    @Test
    public void testGetRolePermissions() {
        String accessToken = "my-access-token";
        GitLabClient client = new GitLabClient(accessToken);
        List<Permissions> permissions = client.getRolePermissions(GitLabRole.DEVELOPER);
        Assert.assertNotNull(permissions);
        Assert.assertEquals(6, permissions.size()); // assume some permissions are returned
    }

    @Test
    public void testJsonToList() {
        String accessToken = "my-access-token";
        GitLabClient client = new GitLabClient(accessToken);
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("item1");
        jsonArray.add("item2");
        List<String> list = client.jsonToList(jsonArray);
        Assert.assertNotNull(list);
        Assert.assertEquals(2, list.size()); // assume 2 items are returned
        Assert.assertEquals("item1", list.get(0));
        Assert.assertEquals("item2", list.get(1));
    }

}
