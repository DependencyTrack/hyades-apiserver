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
package org.dependencytrack.dex.workflow;

import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.activity.PublishNotificationActivity;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowExecutor;
import org.dependencytrack.dex.api.annotation.Workflow;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.workflow.proto.v1.DeleteFilesArgument;
import org.dependencytrack.dex.workflow.proto.v1.PublishNotificationArgument;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * @since 5.7.0
 */
@Workflow(name = "publish-notification")
public final class PublishNotificationWorkflow implements WorkflowExecutor<PublishNotificationArgument, Void> {

    @Override
    public @Nullable Void execute(
            WorkflowContext<PublishNotificationArgument> ctx,
            @Nullable PublishNotificationArgument argument) throws Exception {
        if (argument == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        ctx.logger().debug("Scheduling publishing of notification {}", argument.getNotificationId());

        try {
            ctx.activity(PublishNotificationActivity.class).call(argument).await();
        } catch (RuntimeException e) {
            ctx.logger().warn("Failed to publish notification {}", argument.getNotificationId(), e);
            maybeDeleteNotificationFile(ctx, argument);
            throw e;
        }

        maybeDeleteNotificationFile(ctx, argument);

        return null;
    }

    private void maybeDeleteNotificationFile(
            WorkflowContext<?> ctx,
            PublishNotificationArgument argument) {
        if (!argument.hasNotificationFileMetadata()) {
            return;
        }

        ctx.logger().debug(
                "Scheduling notification file {} for deletion",
                argument.getNotificationFileMetadata().getLocation());

        try {
            ctx.activity(DeleteFilesActivity.class).call(
                    new ActivityCallOptions<DeleteFilesArgument>()
                            .withRetryPolicy(RetryPolicy.ofDefault()
                                    .withInitialDelay(Duration.ofSeconds(1))
                                    .withMaxDelay(Duration.ofSeconds(10))
                                    .withMaxAttempts(3))
                            .withArgument(DeleteFilesArgument.newBuilder()
                                    .addFileMetadata(argument.getNotificationFileMetadata())
                                    .build())).await();
        } catch (ActivityFailureException e) {
            ctx.logger().warn("Failed to delete notification file {}",
                    argument.getNotificationFileMetadata().getLocation(),
                    e.getCause());
        }
    }

}
