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

import com.google.protobuf.util.Timestamps;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskCompleted;
import org.dependencytrack.proto.workflow.v1alpha1.ActivityTaskFailed;
import org.dependencytrack.proto.workflow.v1alpha1.WorkflowEvent;
import org.dependencytrack.workflow.payload.PayloadConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

final class ActivityTaskProcessor<A, R> implements TaskProcessor<ActivityTask> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityTaskProcessor.class);

    private final WorkflowEngine engine;
    private final String activityName;
    private final ActivityRunner<A, R> activityRunner;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;

    public ActivityTaskProcessor(
            final WorkflowEngine engine,
            final String activityName,
            final ActivityRunner<A, R> activityRunner,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter) {
        this.engine = engine;
        this.activityName = activityName;
        this.activityRunner = activityRunner;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
    }

    @Override
    public List<ActivityTask> poll(final int limit) {
        return engine.pollActivityTasks(activityName, limit);
    }

    @Override
    public void process(final ActivityTask task) {
        final var ctx = new ActivityRunContext<>(
                engine,
                task.workflowRunId(),
                task.sequenceNumber(),
                argumentConverter.convertFromPayload(task.argument()),
                activityRunner,
                task.lockedUntil());

        try {
            final Optional<R> result = activityRunner.run(ctx);

            try {
                final var subjectBuilder = ActivityTaskCompleted.newBuilder()
                        .setTaskScheduledEventId(task.sequenceNumber());
                result.ifPresent(r -> subjectBuilder.setResult(resultConverter.convertToPayload(r)));

                engine.completeActivityTask(task,
                        WorkflowEvent.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setActivityTaskCompleted(subjectBuilder.build())
                                .build()).join();
            } catch (InterruptedException | TimeoutException e) {
                throw new RuntimeException(e);
            }
        } catch (Exception e) {
            try {
                engine.completeActivityTask(task,
                        WorkflowEvent.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setActivityTaskFailed(ActivityTaskFailed.newBuilder()
                                        .setTaskScheduledEventId(task.sequenceNumber())
                                        .setFailureDetails(ExceptionUtils.getMessage(e))
                                        .build())
                                .build()).join();
            } catch (InterruptedException | TimeoutException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    @Override
    public void abandon(final ActivityTask task) {
        try {
            // TODO: Add retry?
            engine.abandonActivityTask(task).join();
        } catch (InterruptedException | TimeoutException ex) {
            throw new RuntimeException(ex);
        }
    }

}
