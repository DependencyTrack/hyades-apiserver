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
package org.dependencytrack.notification.vo;

import org.dependencytrack.model.Project;
import org.dependencytrack.proto.notification.v1.ProjectVulnAnalysisStatus;

import java.util.List;
import java.util.UUID;

public class ProjectVulnAnalysisComplete {

    private UUID token;
    private final Project project;
    private final List<ComponentVulnAnalysisComplete> findingsList;
    private final ProjectVulnAnalysisStatus status;

    public ProjectVulnAnalysisComplete(final UUID token, Project project, List<ComponentVulnAnalysisComplete> findingsList, ProjectVulnAnalysisStatus status) {
        this.token = token;
        this.project = project;
        this.findingsList = findingsList;
        this.status = status;
    }

    public UUID getToken() {
        return token;
    }

    public List<ComponentVulnAnalysisComplete> getComponentAnalysisCompleteList() {
        return findingsList;
    }

    public Project getProject() {
        return this.project;
    }

    public ProjectVulnAnalysisStatus getStatus() {
        return status;
    }
}
