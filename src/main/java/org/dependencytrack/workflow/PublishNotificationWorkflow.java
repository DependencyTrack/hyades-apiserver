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
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.Awaitable;
import org.dependencytrack.workflow.framework.RetryPolicy;
import org.dependencytrack.workflow.framework.WorkflowContext;
import org.dependencytrack.workflow.framework.WorkflowExecutor;
import org.dependencytrack.workflow.framework.annotation.Workflow;
import org.dependencytrack.workflow.framework.failure.ActivityFailureException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.dependencytrack.workflow.framework.payload.PayloadConverters.voidConverter;

@Workflow(name = "publish-notification")
public class PublishNotificationWorkflow implements WorkflowExecutor<PublishNotificationWorkflowArgs, Void> {

    @Override
    public Optional<Void> execute(final WorkflowContext<PublishNotificationWorkflowArgs, Void> ctx) throws Exception {
        final PublishNotificationWorkflowArgs args = ctx.argument().orElseThrow();
        if (args.getNotificationRuleNamesCount() == 0) {
            ctx.logger().warn("No rules provided");
            return Optional.empty();
        }

        final var awaitableByRuleName = new HashMap<String, Awaitable<Void>>(args.getNotificationRuleNamesCount());
        for (final String ruleName : args.getNotificationRuleNamesList()) {
            ctx.logger().debug("Scheduling notification publish for rule {}", ruleName);
            final Awaitable<Void> awaitable = PublishNotificationActivity.CLIENT.call(
                    ctx,
                    PublishNotificationActivityArgs.newBuilder()
                            .setNotificationFileMetadata(args.getNotificationFileMetadata())
                            .setNotificationRuleName(ruleName)
                            .build(),
                    RetryPolicy.defaultRetryPolicy()
                            .withMaxAttempts(6));
            awaitableByRuleName.put(ruleName, awaitable);
        }

        for (final Map.Entry<String, Awaitable<Void>> entry : awaitableByRuleName.entrySet()) {
            final String ruleName = entry.getKey();
            final Awaitable<Void> awaitable = entry.getValue();

            try {
                awaitable.await();
            } catch (ActivityFailureException e) {
                ctx.logger().warn("Failed to publish notification for rule {}", ruleName, e.getCause());
            }
        }

        ctx.sideEffect("delete notification file", null, voidConverter(), ignored -> {
            try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
                fileStorage.delete(args.getNotificationFileMetadata());
            } catch (IOException e) {
                ctx.logger().warn("Failed to delete notification file", e);
            }

            return null;
        });

        return Optional.empty();
    }

}
