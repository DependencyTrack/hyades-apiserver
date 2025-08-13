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
package org.dependencytrack.workflow.mapping;

import org.dependencytrack.model.Project;
import org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.resources.v1.vo.CloneProjectRequest;

import java.util.ArrayList;

/**
 * @since 5.7.0
 */
public final class PayloadModelConverter {

    private PayloadModelConverter() {
    }

    public static ProjectIdentity convertToProjectIdentity(final Project project) {
        final var builder = ProjectIdentity.newBuilder()
                .setUuid(project.getUuid().toString())
                .setName(project.getName());
        if (project.getGroup() != null) {
            builder.setGroup(project.getGroup());
        }
        if (project.getVersion() != null) {
            builder.setVersion(project.getVersion());
        }
        return builder.build();
    }

    public static CloneProjectArgs convertToCloneProjectArgs(
            final CloneProjectRequest request,
            final Project sourceProject) {
        final var builder = CloneProjectArgs.newBuilder()
                .setSourceProject(convertToProjectIdentity(sourceProject))
                .setTargetVersion(request.getVersion())
                .setIsTargetVersionLatest(request.makeCloneLatest());

        final var includes = new ArrayList<CloneProjectArgs.Include>(
                CloneProjectArgs.Include.values().length);
        if (request.includeComponents() || request.includeDependencies()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_COMPONENTS);
        }
        if (request.includeServices()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_SERVICES);
        }
        if (request.includeTags()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_TAGS);
        }
        if (request.includeProperties()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_PROPERTIES);
        }
        if (request.includeACL()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_ACL);
        }
        if (request.includeAuditHistory()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_AUDIT_HISTORY);
        }
        if (request.includePolicyViolations()) {
            includes.add(CloneProjectArgs.Include.INCLUDE_POLICY_VIOLATIONS);
        }

        return builder.addAllIncludes(includes).build();
    }

}
