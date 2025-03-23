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
package org.dependencytrack.workflow;

import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.workflow.framework.ActivityContext;
import org.dependencytrack.workflow.framework.ActivityExecutor;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;
import org.dependencytrack.workflow.payload.proto.v1alpha1.CloneProjectArgs;
import org.dependencytrack.workflow.payload.proto.v1alpha1.CloneProjectResult;

import java.util.Optional;
import java.util.UUID;

@Activity(name = "clone-project")
public class CloneProjectActivity implements ActivityExecutor<CloneProjectArgs, CloneProjectResult> {

    @Override
    public Optional<CloneProjectResult> execute(final ActivityContext<CloneProjectArgs> ctx) throws Exception {
        final CloneProjectArgs args = ctx.argument().orElseThrow(ApplicationFailureException::forMissingArguments);

        final Project clonedProject;
        try (final var qm = new QueryManager()) {
            clonedProject = qm.clone(
                    UUID.fromString(args.getProject().getUuid()),
                    args.getNewVersion(),
                    args.getIncludeTags(),
                    args.getIncludeProperties(),
                    args.getIncludeComponents(),
                    args.getIncludeServices(),
                    args.getIncludeAuditHistory(),
                    args.getIncludeAcl(),
                    args.getIncludePolicyViolations(),
                    args.getMakeCloneLatest());
        }

        final var cloneResult = CloneProjectResult.newBuilder()
                .setClonedProject(org.dependencytrack.workflow.payload.proto.v1alpha1.Project.newBuilder()
                        .setUuid(clonedProject.getUuid().toString())
                        .setName(clonedProject.getName())
                        .setVersion(clonedProject.getVersion()))
                .build();

        return Optional.of(cloneResult);
    }

}
