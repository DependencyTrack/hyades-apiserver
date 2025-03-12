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

import org.dependencytrack.proto.workflow.payload.v1alpha1.CloneProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.CloneProjectResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.UpdateProjectMetricsArgs;
import org.dependencytrack.tasks.metrics.ProjectMetricsUpdateTask;
import org.dependencytrack.workflow.framework.WorkflowContext;
import org.dependencytrack.workflow.framework.WorkflowExecutor;
import org.dependencytrack.workflow.framework.annotation.Workflow;
import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;

import java.util.Optional;

import static org.dependencytrack.workflow.framework.RetryPolicy.defaultRetryPolicy;

@Workflow(name = "clone-project")
public class CloneProjectWorkflow implements WorkflowExecutor<CloneProjectArgs, CloneProjectResult> {

    @Override
    public Optional<CloneProjectResult> execute(final WorkflowContext<CloneProjectArgs, CloneProjectResult> ctx) throws Exception {
        final CloneProjectArgs args = ctx.argument().orElseThrow(ApplicationFailureException::forMissingArguments);

        ctx.logger().info("Scheduling cloning of project {}", args.getProject().getUuid());
        final CloneProjectResult cloneResult = CloneProjectActivity.CLIENT.call(
                ctx, args, defaultRetryPolicy()).await().orElseThrow(ApplicationFailureException::forMissingResult);

        ctx.logger().info(
                "Scheduling metrics update for cloned project {}",
                cloneResult.getClonedProject().getUuid());
        final var updateMetricsArgs = UpdateProjectMetricsArgs.newBuilder()
                .setProject(cloneResult.getClonedProject())
                .build();
        ProjectMetricsUpdateTask.ACTIVITY_CLIENT.call(ctx, updateMetricsArgs, defaultRetryPolicy()).await();

        return Optional.of(cloneResult);
    }

}
