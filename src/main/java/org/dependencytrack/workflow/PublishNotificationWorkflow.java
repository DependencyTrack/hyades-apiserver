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

import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.workflow.payload.v1alpha1.PublishNotificationActivityArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.PublishNotificationWorkflowArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.PublishNotificationWorkflowArgs.PublishNotificationTask;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.Awaitable;
import org.dependencytrack.workflow.framework.RetryPolicy;
import org.dependencytrack.workflow.framework.WorkflowRunContext;
import org.dependencytrack.workflow.framework.WorkflowRunner;
import org.dependencytrack.workflow.framework.annotation.Workflow;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.dependencytrack.workflow.framework.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Workflow(name = "publish-notification")
public class PublishNotificationWorkflow implements WorkflowRunner<PublishNotificationWorkflowArgs, Void> {

    @Override
    public Optional<Void> run(final WorkflowRunContext<PublishNotificationWorkflowArgs, Void> ctx) throws Exception {
        final PublishNotificationWorkflowArgs args = ctx.argument().orElseThrow();
        if (args.getTasksCount() == 0) {
            ctx.logger().warn("No publish tasks provided");
            return Optional.empty();
        }

        final var awaitableByTask = new HashMap<PublishNotificationTask, Awaitable<Void>>(args.getTasksCount());
        for (final PublishNotificationTask task : args.getTasksList()) {
            ctx.logger().debug(
                    "Scheduling notification publish for rule {} and publisher {}",
                    task.getRuleName(), task.getPublisherName());
            final Awaitable<Void> awaitable = ctx.callActivity(
                    PublishNotificationActivity.class,
                    PublishNotificationActivityArgs.newBuilder()
                            .setNotificationFileMetadata(args.getNotificationFileMetadata())
                            .setRuleName(task.getRuleName())
                            .setPublisherName(task.getPublisherName())
                            .build(),
                    protoConverter(PublishNotificationActivityArgs.class),
                    voidConverter(),
                    RetryPolicy.defaultRetryPolicy()
                            .withMaxAttempts(6));
            awaitableByTask.put(task, awaitable);
        }

        for (final Map.Entry<PublishNotificationTask, Awaitable<Void>> entry : awaitableByTask.entrySet()) {
            final PublishNotificationTask task = entry.getKey();
            final Awaitable<Void> awaitable = entry.getValue();

            try {
                awaitable.await();
            } catch (RuntimeException e) {
                ctx.logger().warn(
                        "Failed to publish notification for rule {} and publisher {}",
                        task.getRuleName(), task.getPublisherName(), e);
            }
        }

        ctx.sideEffect("delete notification file", null, voidConverter(), ignored -> {
            try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
                fileStorage.delete(args.getNotificationFileMetadata().getKey());
            } catch (IOException e) {
                ctx.logger().warn("Failed to delete notification file", e);
            }

            return null;
        });

        return Optional.empty();
    }

}
