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
package org.dependencytrack.workflow.engine.api;

import org.dependencytrack.workflow.api.ActivityContext;
import org.dependencytrack.workflow.api.ActivityExecutor;
import org.dependencytrack.workflow.api.annotation.Activity;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ActivityGroupTest {

    @Test
    void shouldThrowWhenNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new ActivityGroup(null))
                .withMessage("name must not be null");
    }

    @Test
    void shouldThrowWhenActivityNamesIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new ActivityGroup("name", null, "queue", 1))
                .withMessage("activityNames must not be null");
    }

    @Test
    void shouldThrowWhenQueueNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new ActivityGroup("name", Set.of("activity"), null, 1))
                .withMessage("queueName must not be null");
    }

    @Test
    void withActivityShouldAddActivityByName() {
        final var group = new ActivityGroup("name")
                .withActivity("foo");

        assertThat(group.activityNames()).containsOnly("foo");
    }

    @Activity(name = "foo")
    static class TestActivity implements ActivityExecutor<Void, Void> {

        @Override
        public Void execute(final @NonNull ActivityContext ctx, final Void arg) {
            return null;
        }

    }

    @Test
    void withActivityShouldAddActivityByExecutorClass() {
        final var group = new ActivityGroup("name")
                .withActivity(TestActivity.class);

        assertThat(group.activityNames()).containsOnly("foo");
    }

    static class TestActivityWithoutAnnotation implements ActivityExecutor<Void, Void> {

        @Override
        public Void execute(final @NonNull ActivityContext ctx, final Void arg) {
            return null;
        }

    }

    @Test
    void withActivityShouldThrowWhenActivityExecutorClassIsMissingAnnotation() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new ActivityGroup("name").withActivity(TestActivityWithoutAnnotation.class))
                .withMessage("""
                        No @org.dependencytrack.workflow.api.annotation.Activity annotation found for executor \
                        org.dependencytrack.workflow.engine.api.ActivityGroupTest$TestActivityWithoutAnnotation""");
    }

    @Test
    void withMaxConcurrencyShouldSetMaxConcurrency() {
        final var group = new ActivityGroup("name")
                .withMaxConcurrency(666);

        assertThat(group.maxConcurrency()).isEqualTo(666);
    }

    @Test
    void withMaxConcurrencyShouldThrowWhenMaxConcurrencyIsZeroOrNegative() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new ActivityGroup("name").withMaxConcurrency(-1))
                .withMessage("maxConcurrency must be greater than 0");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new ActivityGroup("name").withMaxConcurrency(0))
                .withMessage("maxConcurrency must be greater than 0");
    }

}