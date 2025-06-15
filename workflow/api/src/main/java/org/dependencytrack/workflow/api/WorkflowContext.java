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
package org.dependencytrack.workflow.api;

import org.dependencytrack.workflow.api.failure.CancellationFailureException;
import org.dependencytrack.workflow.api.failure.SideEffectFailureException;
import org.dependencytrack.workflow.api.payload.PayloadConverter;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * Context available to {@link WorkflowExecutor}s.
 *
 * @param <A> Type of the workflow's argument.
 */
public interface WorkflowContext<A> {

    UUID runId();

    String workflowName();

    int workflowVersion();

    @Nullable
    Map<String, String> labels();

    @Nullable
    A argument();

    /**
     * @return The current, deterministic time within the workflow execution.
     */
    @Nullable
    Instant currentTime();

    /**
     * @return Whether the workflow is currently replaying past events.
     */
    boolean isReplaying();

    /**
     * @return A {@link Logger} to be used for logging within the workflow execution.
     * The {@link Logger} omits log events if the workflow is currently replaying past events,
     * avoiding redundant log emission.
     * @see #isReplaying()
     */
    Logger logger();

    <AA, AR> ActivityClient<AA, AR> activityClient(Class<? extends ActivityExecutor<AA, AR>> activityClass);

    <WA, WR> WorkflowClient<WA, WR> workflowClient(Class<? extends WorkflowExecutor<WA, WR>> workflowClass);

    /**
     * Schedules a durable timer.
     *
     * @param name  Name of the timer. Purely descriptive to make it recognizable in the journal.
     * @param delay {@link Duration} for how far in the future the timer shall elapse.
     * @return An {@link Awaitable} for when the timer elapses.
     */
    Awaitable<Void> scheduleTimer(String name, Duration delay);

    /**
     * Sets a custom status for the workflow run.
     * <p>
     * Does not overwrite the runtime status of the workflow run.
     * <p>
     * May be useful for workflows that are observed by end users, requiring more descriptive
     * and more granular statuses.
     *
     * @param status The status to set. May be {@code null} to reset the custom status.
     */
    void setStatus(@Nullable String status);

    /**
     * Execute a side effect and record its result in the journal.
     * <p>
     * Calling {@link Awaitable#await()} on the {@link Awaitable} returned by this method
     * will throw an {@link SideEffectFailureException} if the side effect failed.
     *
     * @param name               Name of the side effect. Purely descriptive to make it recognizable in the journal.
     * @param argument           Argument to pass to {@code sideEffectFunction}.
     * @param resultConverter    {@link PayloadConverter} to use for the side effect's result.
     * @param sideEffectFunction The side effect to execute.
     * @param <SA>               Type of the side effect's argument.
     * @param <SR>               Type of the side effect's result.
     * @return An {@link Awaitable} wrapping the side effect's result, if any.
     */
    <SA, SR> Awaitable<SR> sideEffect(
            String name,
            @Nullable SA argument,
            PayloadConverter<SR> resultConverter,
            Function<SA, SR> sideEffectFunction);

    /**
     * Wait for an external event.
     * <p>
     * Calling {@link Awaitable#await()} on the {@link Awaitable} returned by this method
     * will throw a {@link CancellationFailureException} if the event is not received before
     * {@code timeout} elapses.
     *
     * @param externalEventId ID of the external event.
     * @param resultConverter {@link PayloadConverter} for the external event's content.
     * @param timeout         {@link Duration} to wait at most for the external event to arrive.
     * @param <ER>            Type of the external event's content.
     * @return An {@link Awaitable} wrapping the external event's content, if any.
     */
    <ER> Awaitable<ER> waitForExternalEvent(
            String externalEventId,
            PayloadConverter<ER> resultConverter,
            Duration timeout);

    /**
     * Restart this workflow with a truncated journal.
     * <p>
     * May be used to prevent the journal from growing too large.
     *
     * @param options Options for the restarted workflow.
     */
    void continueAsNew(ContinueAsNewOptions<A> options);

}
