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

import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

/**
 * Representation of a GitLab project.
 *
 * @author Allen Shearin
 */
class GitLabProject {

    class MaxAccessLevel {

        private final GitLabRole stringValue;

        MaxAccessLevel(final GitLabRole role) {
            this.stringValue = role;
        }

        GitLabRole getStringValue() {
            return stringValue;
        }
    }

    private final String name;
    private final String fullPath;
    private final MaxAccessLevel maxAccessLevel;

    GitLabProject(final String name, final String fullPath, final GitLabRole maxAccessLevel) {
        this.name = name;
        this.fullPath = fullPath;
        this.maxAccessLevel = new MaxAccessLevel(maxAccessLevel);
    }

    public String getName() {
        return name;
    }

    public String getFullPath() {
        return fullPath;
    }

    public MaxAccessLevel getMaxAccessLevel() {
        return maxAccessLevel;
    }

    public static GitLabProject parse(final String data) {
        JSONObject obj = JSONValue.parse(data, JSONObject.class);
        String name = obj.getAsString("name");
        String fullPath = obj.getAsString("fullPath");

        JSONObject maxAccessLevel = (JSONObject) obj.get("maxAccessLevel");
        String stringValue = maxAccessLevel.getAsString("stringValue");

        return new GitLabProject(name, fullPath, GitLabRole.valueOf(stringValue));
    }

    @Override
    public String toString() {
        return "%s{name=%s, fullPath=%s, maxAccessLevel=%s}".formatted(
                getClass().getSimpleName(),
                name,
                fullPath,
                maxAccessLevel.getStringValue().toString());
    }

}