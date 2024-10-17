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
package org.dependencytrack.parser.cyclonedx.util;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.cyclonedx.model.Dependency;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

public class DependencyUtil {

    private DependencyUtil() {}
    
    /**
     * Converts {@link Project#getDirectDependencies()} and {@link Component#getDirectDependencies()}
     * references to a CycloneDX dependency graph.
     *
     * @param project    The {@link Project} to generate the graph for
     * @param components The {@link Component}s belonging to {@code project}
     * @return The CycloneDX representation of the {@link Project}'s dependency graph
     */
    public static List<Dependency> generateDependencies(final Project project, final List<Component> components) {
        if (project == null) {
            return Collections.emptyList();
        }

        final var dependencies = new ArrayList<Dependency>();
        final var rootDependency = new Dependency(project.getUuid().toString());
        rootDependency.setDependencies(convertDirectDependencies(project.getDirectDependencies(), components));
        if (hasDependecies(rootDependency)) {
            dependencies.add(rootDependency);
        }

        for (final Component component : components) {
            final var dependency = new Dependency(component.getUuid().toString());
            dependency.setDependencies(convertDirectDependencies(component.getDirectDependencies(), components));
            if (hasDependecies(dependency)) {
                dependencies.add(dependency);
            }
        }

        return dependencies;
    }

    private static boolean hasDependecies(Dependency dependency) {
        return dependency.getDependencies() != null && !dependency.getDependencies().isEmpty();
    }

    private static List<Dependency> convertDirectDependencies(final String directDependenciesRaw, final List<Component> components) {
        if (directDependenciesRaw == null || directDependenciesRaw.isBlank()) {
            return Collections.emptyList();
        }

        final var dependencies = new ArrayList<Dependency>();
        try(final StringReader reader = new StringReader(directDependenciesRaw)) {
            final JSONArray directDependenciesJsonArray = new JSONArray(new JSONTokener(reader));
            directDependenciesJsonArray.forEach(o -> {
                if (o instanceof final JSONObject directDependencyObject) {
                    final String componentUuid = directDependencyObject.optString("uuid", null);
                    if (componentUuid != null && components.stream().map(Component::getUuid).map(UUID::toString).anyMatch(componentUuid::equals)) {
                        dependencies.add(new Dependency(directDependencyObject.getString("uuid")));
                    }
                }
            });
        }

        return dependencies;
    }
}
