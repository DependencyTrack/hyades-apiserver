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
package org.dependencytrack.dex.testing;

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivityExecutor;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowExecutor;
import org.dependencytrack.dex.api.annotation.Activity;
import org.dependencytrack.dex.api.annotation.Workflow;
import org.dependencytrack.dex.engine.api.ActivityTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.WorkflowTaskWorkerOptions;
import org.dependencytrack.dex.engine.api.request.CreateActivityTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowTaskQueueRequest;
import org.jspecify.annotations.Nullable;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowTestRuleTest {

    @ClassRule
    public static final PostgreSQLContainer<?> POSTGRES_CONTAINER =
            new PostgreSQLContainer<>(DockerImageName.parse("postgres:14-alpine"));

    @Rule
    public final WorkflowTestRule workflowTestRule = new WorkflowTestRule(POSTGRES_CONTAINER);

    @Test
    public void shouldExecuteWorkflow() {
        final DexEngine engine = workflowTestRule.getEngine();

        engine.registerWorkflow(
                new TestWorkflow(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));

        engine.registerActivity(
                new TestActivity(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3),
                false);

        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", "default", 1));
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", "default", 1));

        engine.createWorkflowTaskQueue(new CreateWorkflowTaskQueueRequest("default", 10));
        engine.createActivityTaskQueue(new CreateActivityTaskQueueRequest("default", 10));

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>(TestWorkflow.class, "default"));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();
        assertThat(stringConverter().convertFromPayload(run.result())).isEqualTo("foo-bar");
    }

    @Test
    public void shouldSupportMockedActivities() {
        final DexEngine engine = workflowTestRule.getEngine();

        engine.registerWorkflow(
                new TestWorkflow(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.registerWorkflowWorker(new WorkflowTaskWorkerOptions("workflow-worker", "default", 1));

        engine.createWorkflowTaskQueue(new CreateWorkflowTaskQueueRequest("default", 10));

        final var activityMock = mock(TestActivity.class);
        doReturn("mocked").when(activityMock).execute(any(ActivityContext.class), isNull());

        engine.registerActivity(
                activityMock,
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3),
                false);
        engine.registerActivityWorker(new ActivityTaskWorkerOptions("activity-worker", "default", 1));

        engine.createActivityTaskQueue(new CreateActivityTaskQueueRequest("default", 10));

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>(TestWorkflow.class, "default"));

        final WorkflowRun run = workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();
        assertThat(stringConverter().convertFromPayload(run.result())).isEqualTo("foo-mocked");
    }

    @Workflow(name = "test")
    public static class TestWorkflow implements WorkflowExecutor<Void, String> {

        @Override
        public String execute(final WorkflowContext<Void> ctx, final @Nullable Void argument) {
            final String activityResult = ctx.activity(TestActivity.class).call(new ActivityCallOptions<>()).await();
            return "foo-" + activityResult;
        }

    }

    @Activity(name = "test")
    public static class TestActivity implements ActivityExecutor<Void, String> {

        @Override
        public String execute(final ActivityContext ctx, final @Nullable Void argument) {
            return "bar";
        }

    }

}