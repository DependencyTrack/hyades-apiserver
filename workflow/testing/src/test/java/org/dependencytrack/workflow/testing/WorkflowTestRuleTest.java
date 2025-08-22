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
package org.dependencytrack.workflow.testing;

import org.dependencytrack.workflow.api.ActivityCallOptions;
import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.WorkflowContext;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.dependencytrack.workflow.engine.api.ActivityGroup;
import org.dependencytrack.workflow.engine.api.WorkflowEngine;
import org.dependencytrack.workflow.engine.api.WorkflowGroup;
import org.dependencytrack.workflow.engine.api.WorkflowRun;
import org.dependencytrack.workflow.engine.api.WorkflowRunStatus;
import org.dependencytrack.workflow.engine.api.request.CreateWorkflowRunRequest;
import org.jspecify.annotations.Nullable;
import org.junit.Rule;
import org.junit.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.workflow.api.payload.PayloadConverters.voidConverter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class WorkflowTestRuleTest {

    @Rule
    public final WorkflowTestRule workflowTestRule = new WorkflowTestRule();

    @Test
    public void test() {
        final WorkflowEngine engine = workflowTestRule.getEngine();

        engine.registerWorkflow(
                new TestWorkflow(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.mountWorkflows(
                new WorkflowGroup("all")
                        .withWorkflow(TestWorkflow.class));

        engine.registerActivity(
                new TestActivity(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.mountActivities(
                new ActivityGroup("all")
                        .withActivity(TestActivity.class));

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>(TestWorkflow.class));

        workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final WorkflowRun run = engine.getRun(runId);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();
        assertThat(stringConverter().convertFromPayload(run.result())).isEqualTo("foo-bar");
    }

    @Test
    public void testWithActivityMock() {
        final WorkflowEngine engine = workflowTestRule.getEngine();

        engine.registerWorkflow(
                new TestWorkflow(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.mountWorkflows(
                new WorkflowGroup("all")
                        .withWorkflow(TestWorkflow.class));

        final var activityMock = mock(TestActivity.class);
        doReturn("mocked").when(activityMock).execute(any(ActivityContext.class), isNull());

        engine.registerActivity(
                activityMock,
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.mountActivities(
                new ActivityGroup("all")
                        .withActivity(TestActivity.class));

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>(TestWorkflow.class));

        workflowTestRule.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final WorkflowRun run = engine.getRun(runId);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();
        assertThat(stringConverter().convertFromPayload(run.result())).isEqualTo("foo-mocked");
    }

    @Workflow(name = "test")
    public static class TestWorkflow implements WorkflowExecutor<Void, String> {

        @Override
        public String execute(final WorkflowContext<Void> ctx, @Nullable final Void argument) {
            final String activityResult = ctx.activity(TestActivity.class).call(new ActivityCallOptions<>()).await();
            return "foo-" + activityResult;
        }

    }

    @Activity(name = "test")
    public static class TestActivity implements ActivityExecutor<Void, String> {

        @Override
        public String execute(final ActivityContext ctx, @Nullable final Void argument) {
            return "bar";
        }

    }

}