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

import org.dependencytrack.workflow.annotation.Activity;

import java.util.HashSet;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Logical group of activities to be executed on a shared thread pool.
 *
 * @param name           Name of the group.
 * @param activityNames  Names of activities in this group.
 * @param maxConcurrency Number of activities in this group that can be executed concurrently.
 */
public record ActivityGroup(String name, Set<String> activityNames, int maxConcurrency) {

    public ActivityGroup {
        requireNonNull(name, "name must not be null");
        requireNonNull(activityNames, "activityNames must not be null");
    }

    public ActivityGroup(final String name) {
        this(name, new HashSet<>(), 1);
    }

    public ActivityGroup withActivity(final String activityName) {
        this.activityNames.add(activityName);
        return this;
    }

    public ActivityGroup withActivity(final Class<? extends ActivityExecutor<?, ?>> executorClass) {
        requireNonNull(executorClass, "executorClass must not be null");

        final Activity activityAnnotation = executorClass.getAnnotation(Activity.class);
        if (activityAnnotation == null) {
            throw new IllegalArgumentException("No @Activity annotation found for executor " + executorClass.getName());
        }

        this.activityNames.add(activityAnnotation.name());
        return this;
    }

    public ActivityGroup withMaxConcurrency(final int maxConcurrency) {
        if (maxConcurrency < 1) {
            throw new IllegalArgumentException("maxConcurrency must be greater than 0");
        }
        return new ActivityGroup(this.name, this.activityNames, maxConcurrency);
    }

}
