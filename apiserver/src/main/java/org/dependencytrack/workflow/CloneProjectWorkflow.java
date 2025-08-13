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

import org.dependencytrack.proto.internal.workflow.payload.v1.CloneProjectArgs;
import org.dependencytrack.proto.internal.workflow.payload.v1.ProjectIdentity;
import org.dependencytrack.workflow.api.ActivityCallOptions;
import org.dependencytrack.workflow.api.ActivityHandle;
import org.dependencytrack.workflow.api.WorkflowContext;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.dependencytrack.workflow.api.failure.ActivityFailureException;
import org.dependencytrack.workflow.api.failure.TerminalApplicationFailureException;
import org.jspecify.annotations.NonNull;

/**
 * @since 5.7.0
 */
@Workflow(name = "clone-project")
public final class CloneProjectWorkflow implements WorkflowExecutor<CloneProjectArgs, ProjectIdentity> {

    @Override
    public ProjectIdentity execute(
            final @NonNull WorkflowContext<CloneProjectArgs> ctx,
            final CloneProjectArgs args) throws Exception {
        if (args == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        final ActivityHandle<CloneProjectArgs, ProjectIdentity> cloneActivity =
                ctx.activity(CloneProjectActivity.class);
        final ActivityHandle<ProjectIdentity, Void> updateMetricsActivity =
                ctx.activity(UpdateProjectMetricsActivity.class);

        ctx.logger().debug(
                "Scheduling cloning of project {}:{} to version {}",
                args.getSourceProject().getName(),
                args.getSourceProject().getVersion(),
                args.getTargetVersion());
        final ProjectIdentity clonedProjectIdentity = cloneActivity.call(
                new ActivityCallOptions<CloneProjectArgs>()
                        .withArgument(args)).await();
        if (clonedProjectIdentity == null) {
            throw new TerminalApplicationFailureException(
                    "%s did not return the identity of the cloned project".formatted(
                            CloneProjectActivity.class.getSimpleName()));
        }

        if (!args.getUpdateTargetMetrics()) {
            ctx.logger().debug("Metrics update was not requested");
            return clonedProjectIdentity;
        }

        ctx.logger().debug(
                "Scheduling metrics update of project {}:{}",
                clonedProjectIdentity.getName(),
                clonedProjectIdentity.getVersion());
        try {
            updateMetricsActivity.call(
                    new ActivityCallOptions<ProjectIdentity>()
                            .withArgument(clonedProjectIdentity)).await();
        } catch (ActivityFailureException e) {
            // The metrics update failing should not cause the entire
            // workflow to fail. After all, the primary goal of the workflow
            // is the project cloning.
            ctx.logger().warn("Failed to update metrics of cloned project", e);
        }

        return clonedProjectIdentity;
    }

}
