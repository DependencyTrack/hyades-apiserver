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

import org.dependencytrack.workflow.framework.annotation.Activity;
import org.dependencytrack.workflow.framework.payload.PayloadConverter;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class ActivityRegistry {

    record RegisteredActivity<A, R>(
            ActivityExecutor<A, R> executor,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
    }

    private final String name;
    private final Map<String, RegisteredActivity<?, ?>> activityByName = new HashMap<>();

    public ActivityRegistry(final String name) {
        this.name = Objects.requireNonNull(name, "name must not be null");
    }

    public String name() {
        return name;
    }

    public <A, R> ActivityRegistry register(
            final String name,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout,
            final ActivityExecutor<A, R> executor) {
        if (activityByName.containsKey(name)) {
            throw new IllegalStateException("Activity %s is already registered".formatted(name));
        }

        final var registeredExecutor = new RegisteredActivity<>(
                executor, argumentConverter, resultConverter, lockTimeout);
        activityByName.put(name, registeredExecutor);
        return this;
    }

    public <A, R> ActivityRegistry register(
            final ActivityExecutor<A, R> activityExecutor,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Duration lockTimeout) {
        // TODO: Find a better way to do this.
        //  It's only temporary to make testing easier.
        final Class<? extends ActivityExecutor> activityExecutorClass;
        if (activityExecutor instanceof final FaultInjectingActivityExecutor<A, R> executor) {
            activityExecutorClass = executor.delegate().getClass();
        } else {
            activityExecutorClass = activityExecutor.getClass();
        }

        final var activityAnnotation = activityExecutorClass.getAnnotation(Activity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException("activityExecutor class must be annotated with @Activity");
        }

        return register(activityAnnotation.name(), argumentConverter, resultConverter, lockTimeout, activityExecutor);
    }

    @SuppressWarnings("unchecked")
    <A, R> RegisteredActivity<A, R> getActivity(final String name) {
        return (RegisteredActivity<A, R>) activityByName.get(name);
    }

    Map<String, RegisteredActivity<?, ?>> getActivities() {
        return Collections.unmodifiableMap(activityByName);
    }

}
