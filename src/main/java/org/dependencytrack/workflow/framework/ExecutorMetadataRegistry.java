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
package org.dependencytrack.workflow.framework;

import com.google.common.annotations.VisibleForTesting;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.annotation.Workflow;
import org.dependencytrack.workflow.framework.payload.PayloadConverter;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

final class ExecutorMetadataRegistry {

    record WorkflowMetadata<A, R>(
            String name,
            int version,
            WorkflowExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
    }

    record ActivityMetadata<A, R>(
            String name,
            ActivityExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
    }

    private static final Pattern WORKFLOW_NAME_PATTERN = Pattern.compile("^[\\w-]+");
    private static final Pattern ACTIVITY_NAME_PATTERN = WORKFLOW_NAME_PATTERN;

    @SuppressWarnings("rawtypes")
    private final Map<Class<? extends WorkflowExecutor>, WorkflowMetadata> workflowMetadataByExecutorClass = new HashMap<>();

    @SuppressWarnings("rawtypes")
    private final Map<String, WorkflowMetadata> workflowMetadataByName = new HashMap<>();

    @SuppressWarnings("rawtypes")
    private final Map<Class<? extends ActivityExecutor>, ActivityMetadata> activityMetadataByExecutorClass = new HashMap<>();

    @SuppressWarnings("rawtypes")
    private final Map<String, ActivityMetadata> activityMetadataByName = new HashMap<>();

    <A, R> void register(
            final WorkflowExecutor<A, R> executor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        requireNonNull(executor, "executor must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(lockTimeout, "lockTimeout must not be null");

        final Workflow workflowAnnotation = executor.getClass().getAnnotation(Workflow.class);
        if (workflowAnnotation == null) {
            throw new IllegalArgumentException("Executor class must be annotated with @Workflow");
        }

        register(
                workflowAnnotation.name(),
                workflowAnnotation.version(),
                argumentConverter,
                resultConverter,
                lockTimeout,
                executor);
    }

    @VisibleForTesting
    <A, R> void register(
            final String name,
            final int version,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final WorkflowExecutor<A, R> executor) {
        requireValidWorkflowName(name);

        if (workflowMetadataByExecutorClass.containsKey(executor.getClass())) {
            throw new IllegalArgumentException(
                    "A workflow with executor %s is already registered".formatted(
                            executor.getClass().getName()));
        }
        if (workflowMetadataByName.containsKey(name)) {
            throw new IllegalArgumentException(
                    "A workflow with name %s is already registered".formatted(name));
        }

        final var metadata = new WorkflowMetadata<>(
                name,
                version,
                executor,
                argumentConverter,
                resultConverter,
                lockTimeout);
        workflowMetadataByExecutorClass.put(executor.getClass(), metadata);
        workflowMetadataByName.put(name, metadata);
    }

    <A, R> void register(
            final ActivityExecutor<A, R> executor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        requireNonNull(executor, "executor must not be null");
        requireNonNull(argumentConverter, "argumentConverter must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(lockTimeout, "lockTimeout must not be null");

        final Activity activityAnnotation = executor.getClass().getAnnotation(Activity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException("Executor class must be annotated with @Activity");
        }

        register(activityAnnotation.name(), argumentConverter, resultConverter, lockTimeout, executor);
    }

    @VisibleForTesting
    <A, R> void register(
            final String name,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final ActivityExecutor<A, R> executor) {
        requireValidActivityName(name);

        if (activityMetadataByExecutorClass.containsKey(executor.getClass())) {
            throw new IllegalArgumentException(
                    "An activity with executor %s is already registered".formatted(
                            executor.getClass().getName()));
        }
        if (activityMetadataByName.containsKey(name)) {
            throw new IllegalArgumentException(
                    "An activity with name %s is already registered".formatted(name));
        }

        final var metadata = new ActivityMetadata<>(
                name,
                executor,
                argumentConverter,
                resultConverter,
                lockTimeout);
        activityMetadataByExecutorClass.put(executor.getClass(), metadata);
        activityMetadataByName.put(name, metadata);
    }

    @SuppressWarnings("unchecked")
    <A, R> WorkflowMetadata<A, R> getWorkflowMetadata(final Class<? extends WorkflowExecutor<A, R>> executorClass) {
        requireNonNull(executorClass, "executorClass must not be null");

        final var metadata = (WorkflowMetadata<A, R>) workflowMetadataByExecutorClass.get(executorClass);
        if (metadata == null) {
            throw new NoSuchElementException("No workflow for executor %s found".formatted(executorClass.getName()));
        }

        return metadata;
    }

    @SuppressWarnings("rawtypes")
    WorkflowMetadata getWorkflowMetadata(final String workflowName) {
        requireNonNull(workflowName, "workflowName must not be null");

        final WorkflowMetadata metadata = workflowMetadataByName.get(workflowName);
        if (metadata == null) {
            throw new NoSuchElementException("No workflow with name %s found".formatted(workflowName));
        }

        return metadata;
    }

    @SuppressWarnings("unchecked")
    <A, R> ActivityMetadata<A, R> getActivityMetadata(final Class<? extends ActivityExecutor<A, R>> executorClass) {
        requireNonNull(executorClass, "executorClass must not be null");

        final var metadata = (ActivityMetadata<A, R>) activityMetadataByExecutorClass.get(executorClass);
        if (metadata == null) {
            throw new NoSuchElementException("No activity for executor %s found".formatted(executorClass.getName()));
        }

        return metadata;
    }

    @SuppressWarnings("rawtypes")
    ActivityMetadata getActivityMetadata(final String activityName) {
        requireNonNull(activityName, "activityName must not be null");

        final ActivityMetadata metadata = activityMetadataByName.get(activityName);
        if (metadata == null) {
            throw new NoSuchElementException("No activity with name %s found".formatted(activityName));
        }

        return metadata;
    }

    private static void requireValidWorkflowName(final String workflowName) {
        if (!WORKFLOW_NAME_PATTERN.matcher(workflowName).matches()) {
            throw new IllegalArgumentException("workflowName must match " + WORKFLOW_NAME_PATTERN.pattern());
        }
    }

    private static void requireValidActivityName(final String activityName) {
        if (!ACTIVITY_NAME_PATTERN.matcher(activityName).matches()) {
            throw new IllegalArgumentException("activityName must match " + ACTIVITY_NAME_PATTERN.pattern());
        }
    }

}
