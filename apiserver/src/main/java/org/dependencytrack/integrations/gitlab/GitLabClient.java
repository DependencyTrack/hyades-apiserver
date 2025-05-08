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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.HttpClientPool;

import alpine.Config;
import alpine.common.logging.Logger;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

import static org.apache.commons.io.IOUtils.resourceToString;

public class GitLabClient {

    private static final Logger LOGGER = Logger.getLogger(GitLabClient.class);
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    private static final String GRAPHQL_ENDPOINT = "/api/graphql";

    private final String accessToken;
    private final URI baseURL;
    private final Config config;
    private final List<String> topics;

    private final Map<GitLabRole, List<Permissions>> rolePermissions = Map.of(
            GitLabRole.GUEST, List.of(
                    Permissions.VIEW_PORTFOLIO,
                    Permissions.VIEW_VULNERABILITY,
                    Permissions.VIEW_BADGES),
            GitLabRole.PLANNER, List.of(
                    Permissions.VIEW_PORTFOLIO,
                    Permissions.VIEW_VULNERABILITY,
                    Permissions.VIEW_POLICY_VIOLATION,
                    Permissions.VIEW_BADGES),
            GitLabRole.REPORTER, List.of(
                    Permissions.VIEW_PORTFOLIO,
                    Permissions.VIEW_VULNERABILITY,
                    Permissions.VIEW_POLICY_VIOLATION,
                    Permissions.VIEW_BADGES),
            GitLabRole.DEVELOPER, List.of(
                    Permissions.BOM_UPLOAD,
                    Permissions.VIEW_PORTFOLIO,
                    Permissions.PORTFOLIO_MANAGEMENT_READ,
                    Permissions.VIEW_VULNERABILITY,
                    Permissions.VULNERABILITY_ANALYSIS_READ,
                    Permissions.PROJECT_CREATION_UPLOAD),
            GitLabRole.MAINTAINER, List.of(
                    Permissions.BOM_UPLOAD,
                    Permissions.PORTFOLIO_MANAGEMENT,
                    Permissions.PORTFOLIO_MANAGEMENT_CREATE,
                    Permissions.PORTFOLIO_MANAGEMENT_READ,
                    Permissions.PORTFOLIO_MANAGEMENT_UPDATE,
                    Permissions.PORTFOLIO_MANAGEMENT_DELETE,
                    Permissions.VULNERABILITY_ANALYSIS,
                    Permissions.VULNERABILITY_ANALYSIS_CREATE,
                    Permissions.VULNERABILITY_ANALYSIS_READ,
                    Permissions.VULNERABILITY_ANALYSIS_UPDATE,
                    Permissions.POLICY_MANAGEMENT,
                    Permissions.POLICY_MANAGEMENT_CREATE,
                    Permissions.POLICY_MANAGEMENT_READ,
                    Permissions.POLICY_MANAGEMENT_UPDATE,
                    Permissions.POLICY_MANAGEMENT_DELETE),
            GitLabRole.OWNER, List.of(
                    Permissions.ACCESS_MANAGEMENT,
                    Permissions.ACCESS_MANAGEMENT_CREATE,
                    Permissions.ACCESS_MANAGEMENT_READ,
                    Permissions.ACCESS_MANAGEMENT_UPDATE,
                    Permissions.ACCESS_MANAGEMENT_DELETE,
                    Permissions.SYSTEM_CONFIGURATION,
                    Permissions.SYSTEM_CONFIGURATION_CREATE,
                    Permissions.SYSTEM_CONFIGURATION_READ,
                    Permissions.SYSTEM_CONFIGURATION_UPDATE,
                    Permissions.SYSTEM_CONFIGURATION_DELETE,
                    Permissions.TAG_MANAGEMENT,
                    Permissions.TAG_MANAGEMENT_DELETE));

    public GitLabClient(final String accessToken) {
        this(accessToken, Config.getInstance(), null);
    }

    public GitLabClient(final String accessToken, final List<String> topics) {
        this(accessToken, Config.getInstance(), topics);
    }

    public GitLabClient(final String accessToken, final Config config, final List<String> topics) {
        this.config = config;
        this.accessToken = accessToken;
        this.baseURL = URI.create(config.getProperty(Config.AlpineKey.OIDC_ISSUER));
        this.topics = topics;
    }

    public List<GitLabProject> getGitLabProjects() throws IOException, URISyntaxException {
        List<GitLabProject> projects = new ArrayList<>();

        JSONObject variables = new JSONObject();
        JSONObject queryObject = new JSONObject();

        if (topics != null && !topics.isEmpty()) {
            variables.put("includeTopics", true);
            variables.put("topics", topics);
        }

        queryObject.put("query", resourceToString("/graphql/gitlab-projects.graphql", StandardCharsets.UTF_8));

        URIBuilder builder = new URIBuilder(baseURL.toString()).setPath(GRAPHQL_ENDPOINT);

        HttpPost request = new HttpPost(builder.build());
        request.setHeader("Authorization", "Bearer " + accessToken);
        request.setHeader("Content-Type", "application/json");

        while (true) {
            queryObject.put("variables", variables);

            StringEntity entity = new StringEntity(queryObject.toString(), StandardCharsets.UTF_8);
            request.setEntity(entity);

            try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                HttpEntity responseEntity = response.getEntity();

                if (responseEntity == null)
                    break;

                String responseBody = EntityUtils.toString(responseEntity);
                JSONObject responseData = JSONValue.parse(responseBody, JSONObject.class);
                JSONObject dataObject = (JSONObject) responseData.get("data");
                JSONObject projectsObject = (JSONObject) dataObject.get("projects");
                JSONArray nodes = (JSONArray) projectsObject.get("nodes");

                for (Object nodeObject : nodes) {
                    JSONObject node = (JSONObject) nodeObject;
                    projects.add(GitLabProject.parse(node.toJSONString()));
                }

                JSONObject pageInfo = (JSONObject) projectsObject.get("pageInfo");

                if (!(boolean) pageInfo.get("hasNextPage"))
                    break;

                variables.put("cursor", pageInfo.getAsString("endCursor"));
            }
        }

        return projects;
    }

    public List<Permissions> getRolePermissions(final GitLabRole role) {
        return rolePermissions.get(role);
    }

    // JSONArray to ArrayList simple converter
    public ArrayList<String> jsonToList(final JSONArray jsonArray) {
        ArrayList<String> list = new ArrayList<>();

        for (Object o : jsonArray != null ? jsonArray : Collections.emptyList())
            list.add(o.toString());

        return list;
    }

}
